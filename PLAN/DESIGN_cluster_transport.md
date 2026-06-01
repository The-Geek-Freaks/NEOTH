# Cluster Live-Transport — Design Gremium (Session 32, 2026-06-01)

> 4-lens senior-dev gremium, verified against the real cluster code. The build
> order to make SL-01/SL-01b real (NOT deferred). Operator directive: FINISH.

## Lens: OUTBOUND SEND-PATH: cluster/hyperswarm.rs + heartbeat.rs + relay.rs — end-to-end transport design for SL-01 / SL-01b

**Position:** The peer stream IS NOT retained post-handshake anywhere in the current codebase. Every per-peer connection lives as a local variable inside a spawned task, is consumed exclusively by the inbound read loop, and is dropped when that task exits. To build a real send-path you must (1) split each peeroxide::SecretStream into write and read halves, (2) move the write half into a per-peer outbound mpsc channel backed by a sender task, (3) store a map of peer_id -> outbound Sender in a shared PeerStreamRegistry wrapped in Arc<RwLock>, and (4) extend FrameBody with TaskDelegate/TaskResult/GossipSync variants before any SL-01 dispatch can put bytes on the wire. The smallest working real send-path is: PeerStreamRegistry + per-peer mpsc::Sender<WireFrame> + sender task calling stream.write + typed FrameBody extension — zero theater because the SL-01 dispatch site holds the registry Arc and calls registry.send(peer_pub_key_hex, frame).await.

**Findings:**
- The peeroxide SecretStream is NOT retained after handshake: handle_peeroxide_connection takes `mut conn: peeroxide::SwarmConnection` by move, borrows `let stream = &mut conn.peer.stream` locally, and the entire conn is dropped when the task future completes. There is no global peer-stream map anywhere in the codebase.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\hyperswarm.rs:221-228 — `async fn handle_peeroxide_connection(mut conn: peeroxide::SwarmConnection, ...) { let stream = &mut conn.peer.stream; ... }` — conn lives entirely inside the spawned task at line 172.
- The write side of the stream is a peeroxide message-framed Noise SecretStream — each call to `stream.write(&bytes)` sends one complete ciphertext message. It does NOT use the heartbeat::write_framed length-prefix layer; that path is only for the tokio::io::duplex test transport. The outbound send-path must call `stream.write(&cbor_bytes)` directly, NOT write_framed.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\hyperswarm.rs:214-254 — comment 'SecretStream is message-framed by Noise (each write is one ciphertext, each read returns the next plaintext or None on EOF), so this function bypasses the length-prefix layer'. Hello send: `stream.write(&our_hello_bytes).await`.
- The peeroxide SecretStream supports split into independent read/write halves (standard pattern for Noise streams). The stream object at conn.peer.stream must be split so the inbound read loop and the outbound sender task can run concurrently on separate halves without blocking each other.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\hyperswarm.rs:228 — `let stream = &mut conn.peer.stream;` used for both write (lines 252-254) and read (lines 257-362) sequentially, confirming single ownership. The inbound loop at line 346 is an infinite `loop { stream.read().await }` — it would block any outbound write on the same reference forever.
- WAL cluster band 0xEA..=0xEF is confirmed free. The existing 0xE0..=0xE9 are all assigned (0xE0-0xE7 in the original band, 0xE8-0xE9 in the extended C-5 band). The band-assert compile-time checks for 0xE8/0xE9 use range `0xE0..=0xEF` meaning new codes 0xEA..=0xEF fit without changing the existing assert pattern.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\wal\events.rs:1597-1617 — band assertions for CLUSTER_ROLE_CHANGED and CLUSTER_REQUEST_FORWARDED use `< 0xE0 || > 0xEF` (not > 0xE7), so the wider 0xEA..=0xEF range is correctly covered. Comment at line 1189 explicitly states '0xEA..=0xEF reserved'.
- The FrameBody enum (heartbeat.rs) currently has exactly four variants: Hello, Heartbeat, CapabilityUpdate, Goodbye. TaskDelegate, TaskResult, and GossipSync do not exist yet. CBOR + serde will handle unknown fields on old peers if we use #[serde(other)] or version the frame — but existing peers will disconnect on unknown FrameKind values since FrameKind is a non-exhaustive enum.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\heartbeat.rs:96-112 (FrameKind enum) and 139-146 (FrameBody enum) — neither carries #[non_exhaustive] or unknown-variant fallback. handle_inbound_frame at hyperswarm.rs:651-692 does exhaustive match on FrameBody with no wildcard, so it will compile-fail on new variants until updated.
- LeaseScope::ClusterTaskAccept exists and is the SL-01 gate. The permissions gate (permissions::evaluate) is the mandatory check before any task is accepted from a remote peer. The lease store (LeaseStore::active_for / find_covering) maps a subject (peer pub_key_hex from the registry, NOT from the frame payload) to the scope.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\permissions\lease.rs:41-45 — `ClusterTaskAccept` variant exists. The identity to check against MUST come from the registry (cluster/registry.rs PairedPeer::pub_key_hex) that was written by the post-HMAC confirm flow, never from the incoming frame.
- The relay.rs module is types-only (PeerRoster, RelayRegistration, RelayConfig). There is no live transport in the relay module. The actual neoth-relay binary and Hysteria socket plumbing are explicitly deferred ('multi-week follow-ups'). The relay cannot be used as the send-path today.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\relay.rs:1-17 — 'v0.1 scope = registration protocol types + roster + cap enforcement primitives + tests. The actual neoth-relay binary + the Hysteria-side socket plumbing + the relay-to-relay mesh ship in follow-up bites'.
- The existing peer identity chain is: peeroxide Noise keypair (remote_public_key() at conn.remote_public_key()) -> hex-encoded peer_pk_hex emitted to WAL as CLUSTER_PEER_CONNECTED -> separately confirmed into cluster/registry.rs PairedPeer via neoth cluster confirm. The outbound send-path must look up the target by pub_key_hex from the registry, NOT by the session-local peer_id string.  
  _ev:_ c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\neothd\src\cluster\hyperswarm.rs:227 — `let remote_pk_hex = hex_encode(conn.remote_public_key());` is the authoritative identity. Line 334 emits it to WAL as `remote_public_key_hex`. The peer_id string at line 231 is a UUID v7 process-session handle, NOT the stable cluster identity.

**Recommendation:**

Build the send-path in this exact order — each step is a compilable unit with a real test:

STEP 1 — Split the stream and build PeerStreamRegistry (cluster/peer_streams.rs, new file).

```rust
// cluster/peer_streams.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use anyhow::Result;
use crate::cluster::heartbeat::{WireFrame, encode_frame};

/// Outbound send command for one peer.
pub enum OutboundCmd {
    Frame(WireFrame),
    Shutdown,
}

/// Shared registry of per-peer outbound mpsc senders.
/// Key: remote_pk_hex (the peeroxide Noise public key hex — the
/// HMAC-verified identity, never the session peer_id string).
#[derive(Clone, Default)]
pub struct PeerStreamRegistry {
    inner: Arc<RwLock<HashMap<String, mpsc::Sender<OutboundCmd>>>>,
}

impl PeerStreamRegistry {
    pub async fn register(&self, pk_hex: String, tx: mpsc::Sender<OutboundCmd>) {
        self.inner.write().await.insert(pk_hex, tx);
    }

    pub async fn remove(&self, pk_hex: &str) {
        self.inner.write().await.remove(pk_hex);
    }

    /// Send a frame to a peer by their verified pub_key_hex.
    /// Returns Err if the peer is not connected (fail-closed — caller
    /// propagates the error; no silent drop).
    pub async fn send(&self, pk_hex: &str, frame: WireFrame) -> Result<()> {
        let guard = self.inner.read().await;
        let tx = guard.get(pk_hex)
            .ok_or_else(|| anyhow::anyhow!("peer {pk_hex} not connected — task cannot be delegated"))?;
        tx.send(OutboundCmd::Frame(frame)).await
            .map_err(|_| anyhow::anyhow!("peer {pk_hex} sender closed — connection dropped"))
    }
}
```

STEP 2 — Spawn the per-peer sender task inside handle_peeroxide_connection. Replace the current single mutable borrow of `stream` with a split:

```rust
// In handle_peeroxide_connection, after handshake validation completes
// (after the info!("handshake complete") line, before the inbound loop):

// Split the Noise stream into independent halves.
// peeroxide::SecretStream implements split() -> (ReadHalf, WriteHalf).
let (mut read_half, write_half) = conn.peer.stream.split();

// Outbound channel: bounded 64 keeps backpressure; sender task drains it.
let (tx, mut rx) = mpsc::channel::<OutboundCmd>(64);

// Register before spawning so the sender is available immediately.
registry_streams.register(remote_pk_hex.clone(), tx).await;

// Sender task — owns write_half exclusively.
let pk_hex_for_sender = remote_pk_hex.clone();
let sender_task = tokio::spawn(async move {
    let mut wh = write_half;
    while let Some(cmd) = rx.recv().await {
        match cmd {
            OutboundCmd::Frame(frame) => {
                let bytes = match encode_frame(&frame) {
                    Ok(b) => b,
                    Err(e) => { tracing::warn!(error=%e, "encode_frame failed"); continue; }
                };
                // peeroxide write() — Noise-framed, NOT length-prefixed.
                if let Err(e) = wh.write(&bytes).await {
                    tracing::warn!(peer=%pk_hex_for_sender, error=%e, "outbound write failed");
                    break;
                }
            }
            OutboundCmd::Shutdown => break,
        }
    }
});

// Inbound loop now uses read_half only (no write contention).
loop {
    let bytes = match read_half.read().await { ... }
    // ...existing handle_inbound_frame logic unchanged...
}

// On loop exit, clean up.
sender_task.abort();
registry_streams.remove(&remote_pk_hex).await;
```

STEP 3 — Extend FrameBody in heartbeat.rs with the three new variants. Add BEFORE bumping PROTOCOL_VERSION (additive CBOR is forward-safe toward older peers who will log "unknown body kind" and close cleanly — acceptable because task delegation is opt-in and only happens between paired confirmed peers):

```rust
// cluster/heartbeat.rs additions:
pub const PROTOCOL_VERSION: u16 = 2; // bump when TaskDelegate lands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDelegateBody {
    /// Stable task identifier (UUID v7). Correlates with the
    /// 0xEA CLUSTER_TASK_DELEGATED WAL frame on the master.
    pub task_id: String,
    /// Schema version for TaskDelegateBody itself (separate from
    /// PROTOCOL_VERSION so we can evolve the body shape without
    /// a full re-handshake).
    pub body_version: u16,          // = 1
    /// LeaseScope::ClusterTaskAccept lease id that authorises
    /// this delegation. The slave looks it up in its local
    /// LeaseStore and rejects if expired or absent.
    pub lease_id: String,
    /// Stable identifier for the capability the master wants
    /// exercised (e.g. "claude_cli", "local_qwen").
    pub capability: String,
    /// Opaque prompt payload — CBOR bytes of the provider
    /// request envelope. Kept opaque here so heartbeat.rs
    /// doesn't need to know about the provider types.
    pub prompt_cbor: Vec<u8>,
    /// Max tokens the master budgets for this task.
    pub token_budget: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultBody {
    pub task_id: String,          // mirrors TaskDelegateBody::task_id
    pub body_version: u16,        // = 1
    pub lease_id: String,
    /// One of "ok" | "error" | "refused" | "lease_expired"
    pub status: String,
    /// CBOR bytes of the provider response envelope on success.
    pub response_cbor: Option<Vec<u8>>,
    /// Human-redacted error message on failure.
    pub error: Option<String>,
    pub tokens_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSyncBody {
    pub body_version: u16,         // = 1
    /// Lamport vector clock from gossip_wire::VectorClock.
    pub vector_clock: Vec<(String, u64)>,  // (peer_id, counter)
    /// WAL segment digest entries: (event_type, content_hash).
    /// The receiver calls GossipPolicy::should_replicate on each.
    pub entries: Vec<GossipEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEntry {
    pub event_type: u8,
    pub content_hash: [u8; 32],
    pub seq: u64,
}

// Add to FrameKind:
// TaskDelegate,
// TaskResult,
// GossipSync,

// Add to FrameBody:
// TaskDelegate(TaskDelegateBody),
// TaskResult(TaskResultBody),
// GossipSync(GossipSyncBody),
```

STEP 4 — Add three WAL event codes for the new cluster operations. All three fit in 0xEA..=0xEF (confirmed free). Each needs: constant declaration, band-assert entry (use `< 0xE0 || > 0xEF` matching the existing 0xE8/0xE9 pattern), EVENT_NAME_TABLE entry, uniqueness-test entry, and a REAL emit site:

```
0xEA = EVENT_TYPE_CLUSTER_TASK_DELEGATED
       Emitted by the orchestrator's send_task_delegate() AFTER
       PeerStreamRegistry::send() succeeds.
       Payload: {task_id, target_peer_pubkey, lease_id, capability, ts_unix}

0xEB = EVENT_TYPE_CLUSTER_TASK_RESULT_RECEIVED
       Emitted by handle_inbound_frame on a successful TaskResult frame,
       inside the SL-01 accept handler, AFTER lease validation passes.
       Payload: {task_id, from_peer_pubkey, status, tokens_used, ts_unix}

0xEC = EVENT_TYPE_CLUSTER_GOSSIP_SYNC
       Emitted by handle_inbound_frame on GossipSync, AFTER
       GossipPolicy::should_replicate filters the entries.
       Payload: {from_peer_pubkey, entries_received, entries_accepted, ts_unix}
```

The emit sites are not optional. SC-04 hard rule: every new frame kind needs a real runtime consumer that actually calls fire_wal(). The WAL emit for 0xEA goes in the new `cluster::dispatch::send_task_delegate()` function; for 0xEB/0xEC it goes in the new `handle_inbound_frame` match arms.

STEP 5 — SL-01 accept handler. In handle_inbound_frame, add the new arms:

```rust
FrameBody::TaskDelegate(body) => {
    // 1. Look up the lease by body.lease_id in LeaseStore.
    //    The subject to check: the registry's PairedPeer::pub_key_hex
    //    for the handshake-established remote_pk_hex.
    //    NEVER trust body.lease_id alone — always verify against
    //    the HMAC-verified peer identity from the handshake.
    // 2. Call LeaseStore::find_covering(subject, LeaseScope::ClusterTaskAccept).
    // 3. If no covering lease: return Err("no lease for ClusterTaskAccept") — fail-closed.
    // 4. Call permissions::evaluate(Action::ClusterTaskAccept, autonomy_level).
    // 5. On Allow: emit 0xEB WAL, enqueue task for local execution.
    // 6. On Deny: send back TaskResultBody { status: "refused", ... } via the outbound channel.
    Ok(true)
}
FrameBody::TaskResult(body) => {
    // Master receives this after delegating.
    // Look up pending task by body.task_id.
    // Emit 0xEB WAL.
    Ok(true)
}
FrameBody::GossipSync(body) => {
    // Apply GossipPolicy::should_replicate per entry.
    // Emit 0xEC WAL.
    Ok(true)
}
```

STEP 6 — Thread PeerStreamRegistry through spawn_discovery_with_wal. Add it as a new Arc parameter alongside the existing Arc<Mutex<PeerLoadRegistry>>. The daemon's cli::serve path constructs `Arc::new(PeerStreamRegistry::default())` once and passes it down. The SL-01 dispatch site (wherever the orchestrator decides to delegate) holds the same Arc and calls `registry_streams.send(target_pk_hex, delegate_frame).await`.

The send-path data flow end-to-end:
orchestrator picks peer via LeastLoaded::pick_peer -> looks up pub_key_hex from PairedPeer registry -> validates lease covers ClusterTaskAccept -> builds WireFrame{kind: TaskDelegate, body: FrameBody::TaskDelegate(body)} -> calls PeerStreamRegistry::send(pk_hex, frame) -> mpsc::Sender<OutboundCmd>::send -> per-peer sender task dequeues -> encode_frame(&frame) -> peeroxide write_half.write(&bytes) -> Noise encrypted over TCP to the peer -> peer's read_half.read() -> decode_frame -> handle_inbound_frame TaskDelegate arm -> lease check -> permissions::evaluate -> emit 0xEB -> local execution.

**Risks:**
- peeroxide::SecretStream::split() availability: the design assumes peeroxide 1.3.x exposes split() on SecretStream. If it does not (peeroxide API must be verified before coding), the alternative is to wrap the stream in Arc<Mutex<SecretStream>> shared between the inbound and outbound task, serialising all writes through a Mutex. This is safe but adds latency. Verify with `cargo doc --open` for the peeroxide crate before writing the split code.
- PROTOCOL_VERSION bump to 2 will reject all peers still on version 1 at the validate_hello site (heartbeat.rs:316-320). This is correct behavior but means the cluster goes fully offline during a rolling upgrade. Design for this: add a version-negotiation grace window, or keep version 1 and make the new FrameKind variants additive-only (serde unknown-variant handling via #[serde(other)] on FrameKind). The latter is safer for a v0.x daemon.
- The per-peer mpsc channel is bounded at 64 messages. If the sender task's write_half.write() blocks (slow peer, TCP backpressure), the channel fills and PeerStreamRegistry::send() will return a pending future. The SL-01 dispatch site must use a timeout or select! with a fallback to local execution — otherwise one slow peer can block the orchestrator's task assignment path.
- Gossip entries in GossipSyncBody contain content_hash fields (32 bytes each). The MAX_FRAME_BYTES = 64 KiB cap means a single GossipSync can carry at most ~600 entries before the length check in encode_frame triggers. For large WAL divergences the sender must chunk the entries. Add a GossipSyncBody::entries count check in a validate_gossip_sync() function mirroring validate_heartbeat().
- The band-assert for 0xEA..=0xEC must use `< 0xE0 || > 0xEF` (not `> 0xE7`) to match the existing C-5 pattern for 0xE8/0xE9. Using the narrower `> 0xE7` guard would pass compilation but incorrectly prevent 0xEA-0xEF from being used. The events.rs compile-time const block must be verified against both the assertion range and the all_event_codes_are_unique test to avoid a silent code collision.
- The inbound accept handler for TaskDelegate must validate the lease subject against the HMAC-verified pub_key_hex from the connection handshake, never from the FrameBody payload. A hostile peer that changes its body.lease_id after pairing must be rejected. The implementation must pass the peer's registry-confirmed pub_key_hex into handle_inbound_frame as an additional parameter — the current signature only carries peer_id_expected (the session UUID string), which is insufficient for lease lookup.

---

## Lens: Security engineer — fail-closed / trust-boundary lens on the NEOTH cluster OUTBOUND SEND-path for SL-01 (slave accept-task) and SL-01b (WAL gossip)

**Position:** The trust boundary is the peeroxide Noise channel identity (remote_public_key) bound to a HMAC-verified ClusterAnnouncePacket pub_key and an operator-confirmed PairedPeer entry. Every inbound frame MUST be gated at three ordered checkpoints before any effect: (1) transport-layer Noise identity resolves to a registry-confirmed pub_key_hex, (2) a live LeaseStore entry covers that pub_key_hex for the requested scope, (3) the autonomy gate permits the mapped Action. All three checkpoints must be wired with real emit sites and WAL audit frames at 0xEA/0xEB/0xEC — anything less is SC-04 theater.

**Findings:**
- The HMAC-trust boundary fires at announce time (discovery.rs), NOT at frame-accept time inside hyperswarm.rs. After pairing, identity comes from the Noise channel's remote_public_key(), never from the frame payload. handle_peeroxide_connection stores remote_pk_hex = hex_encode(conn.remote_public_key()) at line 227 before touching any frame bytes, and that hex is emitted into the WAL at emit_peer_connected_wal. Every subsequent frame's peer_id is validated against peer_id_expected (the handshake-negotiated string), not a payload-supplied value.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:227 (remote_pk_hex from conn.remote_public_key()), line 657 (handle_inbound_frame peer_id mismatch bail), line 440 (emit_peer_connected_wal carries remote_public_key_hex)
- The cluster_name_hash check in receive_hello / handle_peeroxide_connection is the shared-secret handshake guard. It validates body.cluster_name_hash == derive_topic(cluster_name) before proceeding. This is the first layer for a peer that knows the cluster name but not the HMAC key — however the HMAC gate in discovery.rs::verify_announce (constant-time XOR-accumulate, length-prefixed fields) is only applied on the ANNOUNCE path, not re-verified on every data frame. Frames after handshake are trusted based on Noise channel identity alone.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:306-316 (cluster_name_hash mismatch bail), /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/discovery.rs:179-186 (verify_announce constant-time check)
- The critical gap: handle_peeroxide_connection emits 0xE0 CLUSTER_PEER_CONNECTED with remote_pk_hex but does NOT look up the peer in ClusterRegistry (PairedPeer store in cluster.yaml). A peer whose HMAC-announce was verified once and is now gone from cluster.yaml (revoked) can still complete the Noise handshake and enter the inbound frame loop. The registry lookup is not called from hyperswarm.rs at all — there is no registry::is_paired(remote_pk_hex) guard in handle_peeroxide_connection.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:220-435 (entire handle_peeroxide_connection — no ClusterRegistry import or call), /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/registry.rs:1-79 (ClusterRegistry/PairedPeer — not imported in hyperswarm.rs)
- LeaseStore::active_for exists and is functional. It takes (subject: &str, scope: &LeaseScope, now_unix: i64) and returns bool. CapabilityLease::covers is fail-closed on empty strings in both directions. LeaseScope::ClusterTaskAccept is defined. But there is no call site in hyperswarm.rs or any cluster inbound path that calls lease_store.active_for(remote_pk_hex, &LeaseScope::ClusterTaskAccept, now) before executing a delegated task — the SL-01 gate chain is primitive-complete but has no real wiring consumer (SC-04).  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/permissions/lease.rs:126-132 (covers fail-closed), 216-218 (active_for), 34-45 (LeaseScope::ClusterTaskAccept)
- Action::ClusterTaskAccept does not exist in the Action enum. The Action enum has ClusterPeerPairing but nothing for inbound task delegation. lease_scope_for is exhaustive with no wildcard, so a new ClusterTaskAccept Action variant would force a conscious leasability decision at compile time. This Action variant must be added and mapped to Some(LeaseScope::ClusterTaskAccept) in lease_scope_for for the gate chain to be wirable.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/permissions/mod.rs:49-152 (Action enum — no ClusterTaskAccept variant), 256-283 (lease_scope_for exhaustive match)
- The gossip ACL (should_replicate) is currently a DENYLIST design: GossipTag::DoNotGossip opts events out; GossipTag::Replicate (default) lets them through. The operator must tag every sensitive event. Only raw channel ingress (is_raw_ingress=true) is blocked by default via replicate_raw_ingress=false. All other WAL event types — permissions decisions, lease grants/revokes, profile deltas, MCP tool calls — replicate by default. A paired-but-malicious peer receives the operator's full permission audit chain unless explicitly tagged.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/gossip.rs:169-177 (should_replicate — denylist model), 31-55 (GossipTag default=Replicate)
- WAL codes 0xEA..=0xEF are confirmed free. The events.rs registry lists 0xE8=CLUSTER_ROLE_CHANGED and 0xE9=CLUSTER_REQUEST_FORWARDED as the highest assigned cluster-band codes. The comment at line 1189 explicitly documents 0xEA..=0xEF as reserved for further cluster lifecycle events. The band-assert compile-time checks for 0xE8/0xE9 use range 0xE0..=0xEF (not 0xE7), so new codes in 0xEA..=0xEF fit the band constraint without modifying existing asserts.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/wal/events.rs:1188-1189 (0xEA..=0xEF reserved comment), 1614-1617 (band asserts for 0xE8/0xE9 use 0xE0..=0xEF range)
- The gossip wire GossipFrame carries the sender's PeerId (origin: PeerId) as a payload field. gossip_wire.rs PeerId is defined as pub_key_hex-shaped. If the receive path trusts frame.origin to identify the sender rather than the Noise channel's remote_public_key, this is a pub_key payload-trust violation. GossipFrame.evaluate_acceptance checks the GossipTag and ReplayBudget but does NOT verify that frame.origin matches the authenticated channel identity.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/gossip_wire.rs:147-205 (GossipFrame struct with origin field, evaluate_acceptance — no channel identity check), 39-54 (PeerId is pub_key_hex-shaped string)
- The send_hello / send path in hyperswarm.rs::send_hello uses stream.write() (line 254) on the peeroxide SecretStream which is Noise-encrypted. This is the only outbound write path currently implemented. There is no TaskDelegate or GossipSync frame kind defined in heartbeat.rs FrameKind/FrameBody — so SL-01 task delegation and SL-01b gossip have no wire frame types yet, meaning the send-path transport does not exist even at the type level.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:592-616 (send_hello uses stream.write), /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/heartbeat.rs (not read but FrameKind/FrameBody referenced at hyperswarm.rs:64-67 — only Hello/Heartbeat/CapabilityUpdate/Goodbye)

**Recommendation:**

Build order and exact signatures for the complete SL-01 / SL-01b send-path:

STEP 1 — Close the registry gap in hyperswarm.rs handle_peeroxide_connection.
After the cluster_name_hash handshake succeeds (line 329), add a registry check:
  let registry_guard = load_cluster_registry(neoth_home);   // Arc<ClusterRegistry> threaded in
  if !registry_guard.peers.iter().any(|p| p.pub_key_hex == remote_pk_hex) {
      emit_peer_rejected_wal(wal_writer.as_deref(), &peer_id, "not in paired registry");
      anyhow::bail!("peer {} not in paired registry", &remote_pk_hex[..16]);
  }
The subject identity for ALL downstream gates is always remote_pk_hex from conn.remote_public_key() — NEVER from any frame payload field. Thread Arc<ClusterRegistry> into spawn_discovery_with_wal alongside ClusterWalWriter.

STEP 2 — Add Action::ClusterTaskAccept in permissions/mod.rs.
  /// SL-01: a paired peer is delegating a task to this node for execution.
  /// subject = sender pub_key_hex (from authenticated Noise channel).
  ClusterTaskAccept { delegating_peer_pub_key_hex: String },
In lease_scope_for exhaustive match:
  Action::ClusterTaskAccept { .. } => Some(LeaseScope::ClusterTaskAccept),
In evaluate_strict/standard/elevated/full: mirror ClusterPeerPairing treatment —
Strict=Deny, Standard/Elevated=Confirm, Full=Allow (operator opted into autonomous delegation).

STEP 3 — Add TaskDelegate + GossipSync frame kinds to heartbeat.rs.
  FrameKind: TaskDelegate, GossipSync
  FrameBody::TaskDelegate(TaskDelegateBody { task_id: u64, payload_cbor: Vec<u8>, requester_pub_key_hex: String })
  FrameBody::GossipSync(GossipSyncBody { frames: Vec<GossipFrame> })
CRITICAL: TaskDelegateBody MUST carry requester_pub_key_hex only as metadata for logging — the gate NEVER reads it for identity. Identity = remote_pk_hex from the Noise channel stored before any frame read.

STEP 4 — Wire the SL-01 gate chain in handle_inbound_frame (hyperswarm.rs).
Add an arm for FrameBody::TaskDelegate:
  FrameBody::TaskDelegate(body) => {
      // 1. Identity: subject = peer_id_expected (tied to remote_public_key at handshake)
      let subject = peer_id_expected;   // this is remote_pk_hex stored at connection open
      let now = now_unix_secs() as i64;
      // 2. Lease gate (fail-closed)
      let lease_ok = lease_store.active_for(subject, &LeaseScope::ClusterTaskAccept, now);
      if !lease_ok {
          emit_cluster_task_rejected_wal(wal_writer, subject, body.task_id, "no_active_lease");
          return Ok(true);   // keep connection alive, log and drop the task
      }
      // 3. Autonomy gate
      let action = Action::ClusterTaskAccept { delegating_peer_pub_key_hex: subject.to_string() };
      match permissions::evaluate(&action, autonomy_level) {
          Decision::Allow => {}
          Decision::Confirm(reason) => {
              emit_cluster_task_rejected_wal(wal_writer, subject, body.task_id, &format!("confirm_required: {reason}"));
              return Ok(true);
          }
          Decision::Deny(reason) => {
              emit_cluster_task_rejected_wal(wal_writer, subject, body.task_id, &format!("denied: {reason}"));
              return Ok(true);
          }
      }
      // 4. Accept — emit 0xEA, dispatch task
      emit_cluster_task_accepted_wal(wal_writer, subject, body.task_id, lease_id);
      dispatch_task(body);
      Ok(true)
  }

STEP 5 — Replace gossip denylist with default-deny allowlist.
In gossip.rs, replace should_replicate with a band-filter:
  pub fn band_is_gossipable(event_type: u8) -> bool {
      matches!(event_type,
          // memory / recall (episodes only — semantic, no raw PII)
          0x90..=0x99 |
          // kanban task state (multi-device workflow sync)
          0x70..=0x76 |
          // ground truth additions/imports (shared knowledge)
          0x97..=0x99
      )
  }
This is a default-deny allowlist of bands. The operator can EXPAND it via freedom.yaml::cluster.gossip.extra_bands: [0x01..=0x0F]. Bands that MUST NEVER cross the peer boundary, even if operator tries:
  - 0xA0..=0xAF (permissions/leases — cluster peer must never receive the local node's lease grants)
  - 0xD0..=0xDF (config/self-update — peer must not receive operator's config change log)
  - 0xF0..=0xFF (quota/tombstone — local operational data)
  - 0xB0..=0xBF (profile — operator PII by default; separate opt-in flag profile_gossip)
  - 0x30..=0x3F (channels — raw ingress/egress; replicate_raw_ingress flag already covers this)
The GossipSyncBody receiver in handle_inbound_frame must call band_is_gossipable(frame.event_type) AND GossipFrame.evaluate_acceptance AND verify frame.origin == authenticated remote_pk_hex before merging.

STEP 6 — WAL audit codes (all in 0xEA..=0xEC, band 0xE0..=0xEF confirmed free).
  pub const EVENT_TYPE_CLUSTER_TASK_ACCEPTED: u8 = 0xEA;
  /// Payload: {peer_pub_key_hex, task_id, lease_id, autonomy_level, ts_unix}
  pub const EVENT_TYPE_CLUSTER_TASK_REJECTED: u8 = 0xEB;
  /// Payload: {peer_pub_key_hex, task_id, reason, ts_unix}
  /// reason one of: "no_active_lease" / "confirm_required" / "denied" / "not_in_registry"
  pub const EVENT_TYPE_CLUSTER_WAL_SYNC_SENT: u8 = 0xEC;
  /// Payload: {target_peer_pub_key_hex, frame_count, oldest_ts_unix, newest_ts_unix, ts_unix}

Each needs: const declaration in wal/events.rs + band-assert in the const _ = {} block (use 0xE0..=0xEF range matching existing 0xE8/0xE9 asserts) + entry in EVENT_NAME_TABLE + entry in all_event_codes_are_unique test + real emit site (0xEA/0xEB in handle_inbound_frame TaskDelegate arm; 0xEC in the GossipSync send path).

STEP 7 — Gossip send-path (outbound, SL-01b).
Add fn send_wal_sync<W: AsyncWrite + Unpin>(sink: &mut W, frames: Vec<GossipFrame>) -> Result<()> that:
  1. Filters frames through band_is_gossipable(event_type extracted from frame.payload[0]) AND GossipTag::Replicate AND ReplayBudget::is_within_budget
  2. Wraps accepted frames into FrameBody::GossipSync(GossipSyncBody { frames })
  3. Calls heartbeat::write_framed
  4. Emits 0xEC CLUSTER_WAL_SYNC_SENT into the WAL writer
This function is the ONLY path that puts WAL frames on the wire — no bypass.

STEP 8 — needs_immediate_sync additions in wal/events.rs.
0xEA (CLUSTER_TASK_ACCEPTED) = true (audit anchor for lease chain)
0xEB (CLUSTER_TASK_REJECTED) = true (security signal — must survive crash)
0xEC (CLUSTER_WAL_SYNC_SENT) = false (batchable — informational, actual durability is on the receiving side)

**Risks:**
- SC-04 theater risk is active right now: LeaseStore::active_for, Action::ClusterTaskAccept, and permissions::evaluate all have no caller in the inbound frame path. The lease primitive is complete but entirely unwired — a task delegation arriving over the Noise channel today would have no gate at all.
- Registry-bypass: a peer whose HMAC announce was valid at discovery time but has since been revoked from cluster.yaml can still complete the Noise handshake and enter the inbound loop. handle_peeroxide_connection does not call ClusterRegistry::load or check PairedPeer::pub_key_hex. This must be fixed in step 1 before any task delegation is wired.
- Gossip denylist inversion: the current GossipTag default=Replicate model means lease grants (0xA5), lease revocations (0xA7), autonomy level changes (0xA2/0xA3), and all profile deltas (0xB0..=0xBF) would replicate to paired peers once gossip is wired. A paired-but-malicious peer would receive the full permission audit chain. The band-filter allowlist in step 5 must ship BEFORE the gossip send-path.
- GossipFrame.origin payload trust: the receive path must bind accepted gossip frames to the authenticated Noise channel identity (remote_pk_hex), not to GossipFrame.origin (a payload field). If GossipFrame.origin is used to attribute replicated events in the WAL, a malicious peer can forge attribution of events to other cluster members.
- Action::ClusterTaskAccept does not exist yet — the exhaustive lease_scope_for match means any call to it with an Action variant that maps to ClusterTaskAccept would be a compile error until the variant and its mapping are added. This is the right design but means there is a build step dependency: the Action variant must land before the handle_inbound_frame gate arm can compile.
- Band-assert range inconsistency: 0xE8 and 0xE9 use the range 0xE0..=0xEF in their band asserts (not 0xE7), while 0xE0..=0xE7 use 0xE0..=0xE7. New codes 0xEA..=0xEC should use 0xE0..=0xEF to match the 0xE8/0xE9 precedent, but the existing 0xE0..=0xE7 asserts still use the tighter range. This inconsistency does not cause a bug today but will cause confusion when reviewing band membership — all cluster-band asserts should be normalized to 0xE0..=0xEF.
- LeaseStore is loaded from disk (~/.neoth/leases.json) via a blocking std::fs read. In the async tokio context of handle_peeroxide_connection, this must either be pre-loaded and threaded in as an Arc<RwLock<LeaseStore>> (matching the PeerLoadRegistry Arc<Mutex> pattern already in the code) or called via tokio::task::spawn_blocking. A blocking disk read on the tokio worker thread is a latency hazard under high connection rate.

---

## Lens: integration / no-theater

**Position:** Both SL-01 and SL-01b require one new FrameBody variant (TaskDelegate) added to the existing CBOR heartbeat enum, two new mpsc channels threaded from handle_inbound_frame into serve.rs task-handler and gossip-sender, three free WAL codes (0xEA/0xEB/0xEC), and a gossip-tick spawned beside cluster_audit_task in serve.rs. Every primitive is already present: the inbound loop, the Gate + LeaseStore, GossipFrame/evaluate_acceptance/should_replicate. The only missing pieces are the send-path plumbing that connects them.

**Findings:**
- The ONLY inbound dispatch site for new cluster frame kinds is handle_inbound_frame() in cluster/hyperswarm.rs. It matches on FrameBody variants. A TaskDelegate variant added to FrameBody (in heartbeat.rs) will land here automatically because the match is exhaustive — the compiler enforces it. The real consumer must be wired here; nowhere else receives per-peer frames.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:651-692 — handle_inbound_frame matches FrameBody::{Hello,Heartbeat,CapabilityUpdate,Goodbye}; adding TaskDelegate requires a new arm that sends on the task_tx mpsc sender threaded in from serve.rs
- The per-peer connection task already holds a ClusterWalWriter (Option<Arc<WalWriterHandle>>) and the registry Arc. The SEND-path for outbound frames per peer exists: conn.peer.stream.write(&bytes).await is called in handle_peeroxide_connection step 1 (Hello send). The SAME stream is available in the inbound loop body via the outer function scope — so a gossip sender task can write GossipFrame bytes onto that stream without a separate connection.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:228-254 — stream.write(&our_hello_bytes).await; the stream variable is &mut conn.peer.stream inside handle_peeroxide_connection which owns conn for the full session lifetime
- The autonomy gate for ClusterTaskAccept already exists end-to-end: LeaseScope::ClusterTaskAccept is defined, lease_scope_for() maps it (implicitly via the unleasable list — it is NOT in the unleasable set, meaning it IS coverable), and LeaseStore::active_for(subject, scope, now) is the check. The gate consumer path used in serve.rs (Gate::for_level(autonomy).with_lease_snapshot(&lease_store, &sender_id, now)) is the exact pattern to reuse for a TaskDelegate handler.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/permissions/lease.rs:42,54 — LeaseScope::ClusterTaskAccept variant + as_str='cluster_task_accept'; /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cli/serve.rs:3748-3774 — Gate::for_level(autonomy).with_lease_snapshot() is the pattern already used for ChannelSend
- The trust boundary for inbound TaskDelegate frames is the ALREADY-COMPLETED handshake: handle_peeroxide_connection validates cluster_name_hash (BLAKE2b of cluster name, derived from peeroxide's discovery_key), protocol name, and version before the inbound loop starts. The peer_id established in the Hello round-trip is pinned to the session; handle_inbound_frame enforces frame.peer_id == peer_id_expected on every frame. This is the identity anchor — NOT a payload field. The peer's pub_key_hex from conn.remote_public_key() must be captured at session start and threaded into the task dispatch (not read from the frame body) to satisfy the hard rule.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:227,295-317,657-661 — remote_pk_hex captured from conn.remote_public_key() before any frame processing; peer_id validated on each frame against handshake-established peer_id_expected
- Free WAL cluster-band codes confirmed: 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF are all unassigned. 0xE0-0xE9 are taken. The band-assert pattern for new codes must use 0xE0..=0xEF range (as 0xE8+0xE9 already do at line 1614-1617). Each new code requires: const definition, EVENT_NAME_TABLE entry, uniqueness-test entry, band-assert.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/wal/events.rs:1189 — comment 'Cluster band 0xE0..=0xE9 currently assigned. 0xEA..=0xEF reserved'; 1614-1617 — band asserts for 0xE8+0xE9 use 0xE0..=0xEF range
- GossipFrame.evaluate_acceptance() is the complete receiver-side gate. It composes: tag.is_replicable() (defence-in-depth for DoNotGossip), budget.is_within_budget(timestamp_unix, now), and event_seq <= last_seen_seq dedup. should_replicate(tag, policy, is_raw_ingress) is the emitter-side gate. Both are pure functions with no IO — the transport caller invokes them and acts on the result. Neither has a real call site yet.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/gossip_wire.rs:184-204 — evaluate_acceptance; /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/gossip.rs:169-177 — should_replicate; both have zero callers in serve.rs today
- serve.rs already has the pattern for the gossip sender spawn: cluster_audit_task (lines 1554-1600) is a tokio::spawn with a 5s tick that polls sidecars and appends WAL frames using writer.clone(). The gossip sender tick + the per-WAL-append gossip trigger both need the same writer.clone() + a channel to receive new WAL frame bytes from the WAL writer, or a tail-cursor read from the segment file. The segment_path is available in serve.rs scope.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cli/serve.rs:1554-1600 — cluster_audit_task spawn with POLL_INTERVAL and writer.clone(); 188-192 — segment_path built from wal_dir.join('000001.wal'), available through entire serve scope
- The PeerLoadRegistry in cluster/mod.rs is Arc<Mutex<PeerLoadRegistry>> in hyperswarm. It holds only PeerLoad (tokens_per_sec, healthy, last_observed). The gossip dedup table (origin -> last_seen_seq) and the local VectorClock are NOT present anywhere in the codebase yet — they must be new state threaded alongside the registry.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/mod.rs:250-288 — PeerLoadRegistry: HashMap<String, PeerLoad> only; no seq tracking, no VectorClock field
- Action::ClusterTaskDelegate does NOT exist in the Action enum today. The enum has ClusterPeerPairing but nothing for accepting an inbound delegated task. lease_scope_for() exhaustively matches Action — adding ClusterTaskDelegate requires adding it to the Action enum AND adding a match arm in lease_scope_for() mapping it to Some(LeaseScope::ClusterTaskAccept).  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/permissions/mod.rs:49-151 — Action enum: ClusterPeerPairing at line 98, no TaskDelegate; 256-281 — lease_scope_for match is exhaustive with no wildcard
- The inbound loop in hyperswarm has no mpsc sender; it currently calls handle_inbound_frame which only mutates the registry in-process. To make SL-01 non-theater, handle_inbound_frame must either (a) accept a task_tx: Option<mpsc::Sender<TaskDelegatePayload>> parameter, or (b) return an enum InboundEffect::{Continue, Goodbye, TaskAccepted(payload)} that the loop in handle_peeroxide_connection dispatches on. Pattern (b) is cleaner because handle_inbound_frame is already pub and tested — its signature change is the only breakage.  
  _ev:_ /c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/hyperswarm.rs:651-692 — handle_inbound_frame returns Result<bool>; adding TaskDelegate handling via return value enum avoids threading a sender through a pure-fn boundary

**Recommendation:**

Build in this exact order. Each step is a discrete PR. No step is theater if the next step lands within the same milestone.

--- STEP 1: FrameBody + Action extension (heartbeat.rs + permissions/mod.rs) ---

In `/c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/cluster/heartbeat.rs`:
Add to FrameKind enum: `TaskDelegate`
Add to FrameBody enum:
```rust
TaskDelegate(TaskDelegateBody)
```
Add struct:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDelegateBody {
    /// Opaque task spec bytes (CBOR-encoded kanban TaskSpec or JSON prompt).
    pub spec_bytes: Vec<u8>,
    /// Human-readable task id for audit. NOT a trust anchor — identity
    /// comes from the session's remote_pk_hex, not this field.
    pub task_id: String,
    /// Requested deadline unix-secs; 0 = no deadline.
    pub deadline_unix: i64,
}
```
In `/c/Users/Shadow-PC/CascadeProjects/AGENTER/SRC/neothd/src/permissions/mod.rs`:
Add Action variant:
```rust
/// Accept a task delegated from a paired cluster master. Subject is
/// the master's pub_key_hex (from the handshake, never the payload).
ClusterTaskDelegate { master_pub_key_hex: String },
```
Add to `lease_scope_for` match:
```rust
Action::ClusterTaskDelegate { .. } => Some(LeaseScope::ClusterTaskAccept),
```
Add to `evaluate` match (conservative default — treat like PaidProviderCall, confirm at Standard):
```rust
Action::ClusterTaskDelegate { .. } => Decision::Confirm(
    format!("cluster task delegation from peer requires confirm")
),
```

--- STEP 2: WAL event codes (wal/events.rs) ---

Add three constants after line 1189:
```rust
// SL-01 cluster task band (0xEA..=0xEC)
/// 0xEA CLUSTER_TASK_DELEGATED — master emits when it forwards a task.
pub const EVENT_TYPE_CLUSTER_TASK_DELEGATED: u8 = 0xEA;
/// 0xEB CLUSTER_TASK_ACCEPTED — slave emits when it accepts after gate.
pub const EVENT_TYPE_CLUSTER_TASK_ACCEPTED: u8 = 0xEB;
/// 0xEC CLUSTER_GOSSIP_APPLIED — slave emits when it applies a gossip frame.
pub const EVENT_TYPE_CLUSTER_GOSSIP_APPLIED: u8 = 0xEC;
```
Add to EVENT_NAME_TABLE (after CLUSTER_REQUEST_FORWARDED entry):
```rust
("cluster_task_delegated", EVENT_TYPE_CLUSTER_TASK_DELEGATED),
("cluster_task_accepted", EVENT_TYPE_CLUSTER_TASK_ACCEPTED),
("cluster_gossip_applied", EVENT_TYPE_CLUSTER_GOSSIP_APPLIED),
```
Add to all_event_codes_are_unique test array:
```rust
("CLUSTER_TASK_DELEGATED", EVENT_TYPE_CLUSTER_TASK_DELEGATED),
("CLUSTER_TASK_ACCEPTED",  EVENT_TYPE_CLUSTER_TASK_ACCEPTED),
("CLUSTER_GOSSIP_APPLIED", EVENT_TYPE_CLUSTER_GOSSIP_APPLIED),
```
Add band-asserts after line 1617:
```rust
let _ = [(); 1][(EVENT_TYPE_CLUSTER_TASK_DELEGATED < 0xE0
    || EVENT_TYPE_CLUSTER_TASK_DELEGATED > 0xEF) as usize];
let _ = [(); 1][(EVENT_TYPE_CLUSTER_TASK_ACCEPTED < 0xE0
    || EVENT_TYPE_CLUSTER_TASK_ACCEPTED > 0xEF) as usize];
let _ = [(); 1][(EVENT_TYPE_CLUSTER_GOSSIP_APPLIED < 0xE0
    || EVENT_TYPE_CLUSTER_GOSSIP_APPLIED > 0xEF) as usize];
```

--- STEP 3: handle_inbound_frame return type + TaskDelegate arm (hyperswarm.rs) ---

Change `handle_inbound_frame` signature from `Result<bool>` to:
```rust
pub fn handle_inbound_frame(
    frame: WireFrame,
    peer_id_expected: &str,
    remote_pk_hex: &str,          // NEW: from handshake, never from payload
    capabilities: &mut Vec<String>,
    registry: &Arc<Mutex<PeerLoadRegistry>>,
) -> Result<InboundEffect>
```
Add enum:
```rust
pub enum InboundEffect {
    Continue,
    Goodbye,
    TaskDelegated { body: TaskDelegateBody, master_pk_hex: String },
}
```
Add match arm in handle_inbound_frame:
```rust
FrameBody::TaskDelegate(body) => {
    Ok(InboundEffect::TaskDelegated {
        body,
        master_pk_hex: remote_pk_hex.to_string(),
    })
}
```
Update all callers of handle_inbound_frame (the inbound loop in handle_peeroxide_connection, run_inbound_loop, and all unit tests) to pass remote_pk_hex and match InboundEffect.

In handle_peeroxide_connection, after getting InboundEffect::TaskDelegated, send on a task_tx: Option<mpsc::UnboundedSender<(TaskDelegateBody, String)>> threaded in alongside wal_writer. Best-effort: if tx.send() fails, emit 0xEB with status='rejected_no_consumer'.

--- STEP 4: GossipState struct + gossip sender task (new file cluster/gossip_state.rs) ---

```rust
// cluster/gossip_state.rs
pub struct GossipState {
    pub local_vc: VectorClock,
    pub local_id: PeerId,
    /// last_seen_seq per origin peer — the dedup table for evaluate_acceptance.
    pub seen: std::collections::HashMap<PeerId, u64>,
    pub policy: GossipPolicy,
}

impl GossipState {
    /// Called by the emitter on every WAL append that passes should_replicate.
    pub fn next_frame(&mut self, payload: Vec<u8>, tag: GossipTag) -> Option<GossipFrame> {
        if !should_replicate(tag, &self.policy, false) {
            return None;
        }
        self.local_vc.tick(&self.local_id);
        let seq = self.local_vc.get(&self.local_id);
        Some(GossipFrame {
            vector_clock: self.local_vc.clone(),
            origin: self.local_id.clone(),
            event_seq: seq,
            timestamp_unix: now_unix_secs(),
            tag,
            payload,
        })
    }

    /// Called by the receiver on each inbound GossipFrame.
    pub fn receive(
        &mut self,
        frame: &GossipFrame,
        budget: &ReplayBudget,
        now: i64,
    ) -> GossipAcceptance {
        let last = self.seen.get(&frame.origin).copied();
        let verdict = frame.evaluate_acceptance(budget, now, last);
        if verdict == GossipAcceptance::Accept {
            self.local_vc.merge(&frame.vector_clock);
            self.seen.insert(frame.origin.clone(), frame.event_seq);
        }
        verdict
    }
}
```

--- STEP 5: serve.rs wiring (the end-to-end data-flow) ---

After `let (writer, mut writer_join) = wal_spawn(...)` add:

```rust
// SL-01: task-delegate mpsc channel. hyperswarm per-peer tasks send accepted
// TaskDelegate frames here; the handler task below processes them.
let (task_tx, mut task_rx) =
    tokio::sync::mpsc::unbounded_channel::<(crate::cluster::heartbeat::TaskDelegateBody, String)>();

// SL-01b: gossip state shared across per-peer gossip senders.
let gossip_state = std::sync::Arc::new(tokio::sync::Mutex::new(
    crate::cluster::gossip_state::GossipState::new(
        crate::cluster::gossip_wire::PeerId::new(local_peer_id()),
        crate::cluster::gossip::GossipPolicy::default(),
    )
));
```

Spawn the cluster discovery replacing the current `spawn_discovery` call with:
```rust
let _swarm = crate::cluster::hyperswarm::spawn_discovery_with_wal_and_channels(
    &cluster_name,
    Arc::clone(&peer_registry),
    Some(Arc::clone(&writer)),  // ClusterWalWriter — already the type
    task_tx.clone(),
    Arc::clone(&gossip_state),
).await?;
```
(This requires adding task_tx + gossip_state params to spawn_discovery_with_wal — thread them into each per-peer tokio::spawn closure alongside wal.)

Spawn the SL-01 task-accept handler (after cluster_audit_task spawn):
```rust
let task_accept_task: tokio::task::JoinHandle<()> = {
    let writer_for_tasks = writer.clone();
    let autonomy = config.autonomy;
    tokio::spawn(async move {
        while let Some((body, master_pk_hex)) = task_rx.recv().await {
            // Gate: ClusterTaskDelegate. Subject = master's pub_key_hex
            // from the HANDSHAKE (never from the payload).
            use crate::permissions::{Action, Gate, ConfirmStrategy};
            use crate::permissions::lease::LeaseStore;
            let lease_store = {
                let path = LeaseStore::default_path(
                    &crate::config::FreedomConfig::default_neoth_home(),
                );
                tokio::task::spawn_blocking(move || LeaseStore::load(&path).unwrap_or_default())
                    .await
                    .unwrap_or_default()
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64).unwrap_or(0);
            let action = Action::ClusterTaskDelegate {
                master_pub_key_hex: master_pk_hex.clone(),
            };
            let gate = Gate::for_level(autonomy)
                .with_confirm(ConfirmStrategy::FailClosed)
                .with_lease_snapshot(&lease_store, &master_pk_hex, now);
            match gate.check(&action, Some(&writer_for_tasks)).await {
                Ok(()) => {
                    // Thin shim: emit 0xEB CLUSTER_TASK_ACCEPTED audit frame.
                    // Actual task execution (provider call / kanban row) is
                    // the SL-01-full follow-up; the shim proves the path is
                    // real and gated.
                    let payload = serde_json::to_vec(&serde_json::json!({
                        "task_id": body.task_id,
                        "master_pk_hex": master_pk_hex,
                        "spec_bytes_len": body.spec_bytes.len(),
                        "deadline_unix": body.deadline_unix,
                        "ts_unix": now,
                    })).unwrap_or_default();
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_CLUSTER_TASK_ACCEPTED, &payload
                    ).build();
                    if let Err(e) = writer_for_tasks.append(header, payload).await {
                        tracing::warn!(error = %e, "CLUSTER_TASK_ACCEPTED WAL append failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        task_id = %body.task_id,
                        master = %master_pk_hex,
                        error = %e,
                        "cluster task delegation rejected by autonomy gate"
                    );
                }
            }
        }
    })
};
```

Spawn the SL-01b gossip sender tick (after task_accept_task):
```rust
let gossip_send_task: tokio::task::JoinHandle<()> = {
    let segment_path_for_gossip = segment_path.clone();
    let gossip_state_for_sender = Arc::clone(&gossip_state);
    // peer_streams_tx: a broadcast or registry of per-peer stream senders.
    // Simplest first implementation: a tokio::broadcast::Sender<Vec<u8>>
    // that each per-peer task subscribes to. Capacity 64 frames.
    // (The broadcast sender is passed into spawn_discovery_with_wal_and_channels.)
    let broadcast_tx_for_gossip = gossip_broadcast_tx.clone();
    let writer_for_gossip = writer.clone();
    tokio::spawn(async move {
        use crate::cluster::gossip::{GossipPolicy, ReplayBudget, should_replicate, GossipTag};
        use crate::cluster::gossip_wire::GossipFrame;
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        // Reconcile tick: every 10s scan new WAL tail + broadcast gossip frames.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // WAL cursor: start at end-of-file at daemon boot (peers only catch up
        // to frames written AFTER they connected; a full replay is the re-pair path).
        let mut wal_cursor: u64 = crate::wal::segment_cursor_eof(&segment_path_for_gossip)
            .unwrap_or(0);
        loop {
            ticker.tick().await;
            // Read new WAL frames since cursor.
            let new_frames = match crate::wal::read_frames_since(
                &segment_path_for_gossip, wal_cursor
            ) {
                Ok(v) => v,
                Err(e) => { tracing::warn!(error=%e, "gossip WAL read failed"); continue; }
            };
            let mut state = gossip_state_for_sender.lock().await;
            for (raw_bytes, event_type) in new_frames {
                wal_cursor += raw_bytes.len() as u64;
                // is_raw_ingress: channel-ingress band 0x30..=0x3F
                let is_raw_ingress = (0x30..=0x3F).contains(&event_type);
                let tag = GossipTag::Replicate; // default; future: per-event tag table
                if !should_replicate(tag, &policy, is_raw_ingress) { continue; }
                let Some(frame) = state.next_frame(raw_bytes, tag) else { continue; };
                let frame_bytes = match serde_json::to_vec(&frame) {
                    Ok(b) => b, Err(e) => { tracing::warn!(error=%e, "gossip encode"); continue; }
                };
                // Best-effort broadcast; lagged receivers drop frames (they
                // will re-pair when budget.peer_force_repair() fires on their side).
                let _ = broadcast_tx_for_gossip.send(frame_bytes);
            }
        }
    })
};
```

In each per-peer handle_peeroxide_connection, subscribe to the broadcast + drain inbound gossip:
```rust
// In handle_peeroxide_connection after handshake (step 3 inbound loop):
// Add a gossip receive arm:
let mut gossip_rx = gossip_broadcast_rx; // passed in from serve.rs
loop {
    tokio::select! {
        biased;
        // Outbound gossip: send frames queued by the gossip_send_task.
        Ok(frame_bytes) = gossip_rx.recv() => {
            if let Err(e) = stream.write(&frame_bytes).await {
                warn!(peer_id=%peer_id, error=%e, "gossip send failed");
                break;
            }
        }
        // Inbound: existing frame handling.
        bytes = stream.read() => {
            // existing match block ...
            // When frame.kind == TaskDelegate: send on task_tx
            // When frame.kind == GossipFrame (new FrameKind variant):
            //   call gossip_state.receive(&frame, &budget, now)
            //   if Accept: emit 0xEC + apply payload to local WAL via writer.try_append_sync
        }
    }
}
```

--- END-TO-END DATA FLOW: TaskDelegate ---
Master emits FrameKind::TaskDelegate (CBOR, u32-LE-prefixed) onto peeroxide stream ->
handle_peeroxide_connection inbound loop reads frame ->
handle_inbound_frame returns InboundEffect::TaskDelegated{body, master_pk_hex} (pk from handshake, NOT payload) ->
task_tx.send((body, master_pk_hex)) ->
task_accept_task receives, loads LeaseStore, calls Gate::for_level().with_lease_snapshot().check(Action::ClusterTaskDelegate{..}) ->
gate Allow: emit 0xEB CLUSTER_TASK_ACCEPTED WAL frame; gate Deny/Confirm-closed: log warn, no frame ->
(SL-01-full follow-up: on Allow, deserialize spec_bytes, create kanban row, spawn provider call)

--- END-TO-END DATA FLOW: Gossip WAL Frame ---
Local WAL writer appends frame X to segment ->
gossip_send_task tick reads new bytes since cursor ->
should_replicate(tag, policy, is_raw_ingress) passes ->
GossipState::next_frame() ticks local VectorClock, wraps bytes in GossipFrame, returns Some ->
gossip_broadcast_tx.send(frame_bytes) ->
each per-peer session receives on gossip_broadcast_rx ->
stream.write(frame_bytes) to peer ->

On peer B's side:
stream.read() returns gossip frame bytes ->
deserialize GossipFrame ->
GossipState::receive(&frame, &budget, now_unix) calls evaluate_acceptance ->
DroppedDoNotGossipTag/DroppedDuplicate/DroppedOutsideReplayBudget: log at debug, no-op ->
Accept: local_vc.merge(&frame.vector_clock), seen.insert(origin, seq) ->
writer_b.try_append_sync(WAL_header, frame.payload) — applies the raw WAL bytes to peer B's segment ->
emit 0xEC CLUSTER_GOSSIP_APPLIED {origin, event_seq, ts_unix} for audit

--- BUILD ORDER (no step is theater) ---
1. heartbeat.rs TaskDelegate body + FrameKind variant (compile-breaks handle_inbound_frame match — forces step 2)
2. hyperswarm.rs InboundEffect enum + handle_inbound_frame signature change + TaskDelegate arm + remote_pk_hex threading
3. permissions/mod.rs Action::ClusterTaskDelegate + lease_scope_for arm + evaluate arm
4. wal/events.rs 0xEA/0xEB/0xEC + EVENT_NAME_TABLE + band-asserts + uniqueness test entries
5. cluster/gossip_state.rs GossipState::new/next_frame/receive
6. serve.rs: task_tx channel + gossip_state Arc + spawn_discovery_with_wal_and_channels + task_accept_task + gossip_send_task + abort in shutdown sequence (before writer drop)


**Risks:**
- The gossip broadcast pattern (tokio::broadcast) drops frames for lagged receivers. A peer that falls behind on reading its gossip_rx will silently lose frames. This is acceptable for the thin shim (re-pair is the catch-up path) but must be documented. Alternative: per-peer mpsc queue with bounded backpressure, evict oldest frame on full. Decision needed before SL-01b-full ships.
- WAL bytes written by gossip_send_task to peer B via stream.write are raw WAL frame bytes. Peer B's writer.try_append_sync path writes them back into B's segment. If the WAL frame format ever changes (segment header magic, CRC field), a mixed-version cluster will corrupt B's segment. Pin format version in the GossipFrame.payload metadata field now.
- handle_inbound_frame currently has 8 unit tests that pass two args (frame, peer_id_expected). Adding remote_pk_hex as a third parameter breaks all 8 tests. This is intentional (compile-time enforcement), but must be fixed in the same PR as step 2 — do not merge a broken test suite.
- The gossip_send_task reads WAL frames using a cursor that starts at EOF at daemon boot. Peers that reconnect after a gap receive NO historical frames — they re-pair. This is correct per the 30-day ReplayBudget design but means a peer restart within a 10s gossip tick window can miss frames emitted while it was disconnected. A peer-reconnect replay (send frames from peer's last_seen_unix to now) is a follow-up; do NOT attempt it in the thin shim.
- Action::ClusterTaskDelegate is added with Decision::Confirm at Standard. The daemon has no TTY and serve.rs uses ConfirmStrategy::FailClosed — so Standard effectively DENIES all task delegation. Operators wanting to receive delegated tasks MUST either raise autonomy to Elevated/Full or grant a cluster_task_accept lease to the master's pub_key_hex via neoth lease grant. This must be in the operator-facing docs for SL-01.
- The peer pub_key_hex is from conn.remote_public_key() (peeroxide's Noise layer) which IS the HMAC-verified identity at the transport layer. However the cluster_key HMAC referenced in the GROUND TRUTH is a separate NEOTH-layer check in cluster/policy.rs and cluster/discovery.rs — it authenticates announce packets, not peeroxide stream sessions. The peeroxide Noise handshake is the trust anchor for per-peer sessions. These must not be conflated. Verify that cluster/policy.rs HMAC runs on mDNS/Tailscale discovers before registry.upsert, and that peeroxide's pub_key is the SAME identity as the registry's pub_key_hex — document the binding explicitly.

---

## Lens: pragmatic-staff-engineer / ship-it

**Position:** The outbound SEND-path is the single real blocker. The inbound machinery (read loop, HMAC-gated handshake, WAL emit, registry write) is genuinely complete and tested. The missing piece — a per-connection outbound heartbeat sender task — is a one-day commit: ~80 lines plugged into the existing `handle_peeroxide_connection` function. SL-01b gossip send-path is the harder follow-on (no transport plumbing at all, not just no sender task); SL-01 task-accept dispatch is a one-day commit on top of the outbound sender once heartbeats are live. Build in that order: (1) outbound heartbeat sender, (2) SL-01 task-accept handler, (3) SL-01b gossip transport — and each is a genuinely shippable end-to-end slice.

**Findings:**
- Inbound loop is complete and ship-quality. handle_peeroxide_connection at hyperswarm.rs:220 does full Hello handshake (send + receive + validate cluster_name_hash), then loops on stream.read() → decode_frame → handle_inbound_frame → record_heartbeat_into_registry → WAL emit. The peer identity is taken ONLY from the Noise-authenticated remote_public_key_hex, never from the frame payload.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs:220-435
- The OUTBOUND sender task does not exist. hyperswarm.rs:584-588 comments explicitly: 'sender loop with jittered ticker lands when the daemon ships an internal token-rate meter; today the receive half alone gives the cluster meaningful peer-discovery + health observability'. The function send_hello exists (line 592) and write_framed is in heartbeat.rs:224, but no tokio::spawn drives periodic heartbeat writes from the local node to peers.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs:584-588, c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/heartbeat.rs:224-235, next_jittered_interval at heartbeat.rs:340
- The outbound sender is a one-day commit. All primitives are already present: write_framed (heartbeat.rs:224), next_jittered_interval (heartbeat.rs:340), hash_capabilities (heartbeat.rs:352), validate_heartbeat (heartbeat.rs:264), PeerLoadRegistry (mod.rs:250). The implementation is: inside handle_peeroxide_connection, after the hello round-trip succeeds, tokio::spawn a sender task that loops on tokio::time::sleep(next_jittered_interval(&mut rng)), writes a Heartbeat frame via heartbeat::write_framed, and exits on channel close. This adds ~60 lines.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs:230-254, c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/heartbeat.rs:340-359
- spawn_discovery_with_wal in serve.rs is NOT called. The serve.rs cluster section at line 1549-1601 only spawns the audit-sidecar ingester (confirms/revokes), not the Hyperswarm peer transport. No live cluster transport is wired into the daemon.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cli/serve.rs:1549-1601 (cluster_audit_task is the only cluster code in serve)
- WAL codes 0xEA..=0xEF are confirmed free. The events.rs band comment at line 1189 says 'Cluster band 0xE0..=0xE9 currently assigned. 0xEA..=0xEF reserved for further cluster lifecycle events'. The compile-time band assertions for 0xE8/0xE9 use the widened 0xEF upper bound (lines 1615-1617), not the original 0xE7 bound used for 0xE0-0xE7, confirming the band is open.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/wal/events.rs:1189-1191, lines 1597-1617
- SL-01 task-accept (slave accept path) needs: (a) a new Action::ClusterTaskAccept variant in permissions/mod.rs, (b) a FrameBody variant for TaskRequest in heartbeat.rs or a new message type, (c) an inbound handler branch in handle_inbound_frame that gate-checks LeaseScope::ClusterTaskAccept via Gate::check, runs the task, and returns a TaskResult frame. LeaseScope::ClusterTaskAccept already exists in lease.rs:42.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/permissions/lease.rs:41-42, c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs:663-691
- SL-01b gossip send-path is genuinely larger. gossip_wire.rs has GossipFrame envelope, VectorClock, GossipAcceptance — but there is zero transport plumbing: no send_gossip function, no connection-slot for a peer gossip stream separate from the heartbeat stream, no JSONL append-stream, no dedup table. The comment at gossip_wire.rs:9-12 explicitly lists all of this as follow-up.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/gossip_wire.rs:9-12, gossip.rs:22 (v0.1 scope = primitives + policy types + tests)
- The SC-04 gap (no real runtime consumer) is specifically the missing spawn of spawn_discovery_with_wal in serve.rs. Once that call is added and the outbound sender task lands, every WAL emit site (emit_peer_connected_wal, emit_heartbeat_first_wal, etc.) already has a fire_wal path that calls writer.try_append_sync.  
  _ev:_ c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs:440-570, fire_wal at line 562

**Recommendation:**

BUILD ORDER: three sequential commits, each genuinely complete.

COMMIT 1 — Outbound heartbeat sender (1 day, ~80 lines net):

File: c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs

After the hello round-trip (line 339), before the inbound loop, add:

```rust
// Split the Noise stream into a read half and a write half.
// peeroxide's SwarmConnection gives us `conn.peer.stream`
// which is a full-duplex SecretStream. We need to hold
// a write reference in the sender task AND a read reference
// in the receiver loop. Use an Arc<Mutex<...>> or — better —
// split the stream into two independently-usable halves if
// peeroxide exposes that. If not, pass a tokio::mpsc channel:
// the inbound loop queues frames to write into a channel and a
// tiny sender task drains it, PLUS the heartbeat ticker fires
// into the same sender channel.

let (heartbeat_tx, mut heartbeat_rx) = tokio::sync::mpsc::channel::<WireFrame>(8);
let mut seq: u64 = 1;
// Sender task: ticks every next_jittered_interval and writes one
// Heartbeat frame to the peer.
let sender_task = {
    let tx = heartbeat_tx.clone();
    let peer_id_clone = own_peer_id.clone();
    tokio::spawn(async move {
        let mut rng = rand::thread_rng();
        loop {
            tokio::time::sleep(heartbeat::next_jittered_interval(&mut rng)).await;
            // Read local load from PeerLoadRegistry or a shared AtomicF64.
            let body = HeartbeatBody {
                tokens_per_sec: 0.0, // wire in real meter once available
                inflight_requests: 0,
                healthy: true,
                capabilities_hash: [0u8; 32],
            };
            let frame = WireFrame {
                kind: FrameKind::Heartbeat,
                sequence: seq,
                sent_unix_ms: now_unix_ms(),
                peer_id: peer_id_clone.clone(),
                body: FrameBody::Heartbeat(body),
            };
            seq += 1;
            if tx.send(frame).await.is_err() { break; }
        }
    })
};
// Drain the sender channel onto the stream before reading the next
// inbound frame (simple interleave — no simultaneous r/w needed at
// 5s cadence):
// In the inbound loop, add a tokio::select! between stream.read()
// and heartbeat_rx.recv():
loop {
    tokio::select! {
        bytes = stream.read() => { /* existing inbound handler */ }
        Some(frame) = heartbeat_rx.recv() => {
            let bytes = heartbeat::encode_frame(&frame)?;
            stream.write(&bytes).await?;
        }
    }
}
```

Also in this commit:
- Add `spawn_discovery_with_wal` call in serve.rs after WAL writer is available (after line 210 where the writer exists). Use the daemon's `Arc<WalWriterHandle>` clone. Wire `Arc<Mutex<PeerLoadRegistry>>` from a new daemon-level field so routing eventually reads it.
- Add WAL code `0xEA = EVENT_TYPE_CLUSTER_HEARTBEAT_SENT` for the first local heartbeat sent — free slot confirmed. Add to: events.rs constant, EVENT_NAME_TABLE, band assert (0xEA > 0xE9 and <= 0xEF), uniqueness test array.
- Integration test: two tokio::io::duplex peers, one runs send_hello + sender task, other runs receive_hello + run_inbound_loop, assert registry has one entry after one interval.

COMMIT 2 — SL-01 task-accept handler (1 day, ~120 lines net):

Prerequisites: Commit 1 shipped (live transport exists).

Files to change:
- c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/heartbeat.rs: Add `FrameKind::TaskRequest` and `FrameKind::TaskResult`, plus `TaskRequestBody { task_id: String, payload_json: String }` and `TaskResultBody { task_id: String, ok: bool, output_json: String }` to `FrameBody`. This is additive (CBOR + serde tolerate new variants — existing peers ignore unknown body kinds).
- c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/cluster/hyperswarm.rs: In `handle_inbound_frame`, add a `FrameBody::TaskRequest(body)` match arm that: (a) reads the active LeaseStore from a daemon-injected `Arc<LeaseStore>`, (b) calls `Gate::for_level(level).with_lease_snapshot(&store, peer_pub_key_hex, now_unix).check(&Action::ClusterTaskAccept, Some(wal)).await`, (c) on Allow: runs the task (call into providers dispatch), sends TaskResult frame back via the heartbeat_tx channel, emits `0xEB EVENT_TYPE_CLUSTER_TASK_ACCEPTED` WAL frame, (d) on Deny: sends TaskResult { ok: false } + emits `0xEC EVENT_TYPE_CLUSTER_TASK_REJECTED` WAL frame.
- c:/Users/Shadow-PC/CascadeProjects/AGENTER/src/neothd/src/permissions/mod.rs: Add `Action::ClusterTaskAccept` and map it to `LeaseScope::ClusterTaskAccept` in `lease_scope_for`. The LeaseScope variant already exists at lease.rs:42.
- events.rs: Add 0xEB/0xEC as free cluster-band codes with band assert, EVENT_NAME_TABLE entry, uniqueness test entry.

What 'complete' means for Commit 2: a slave node receives a TaskRequest frame from a peer with a valid `ClusterTaskAccept` lease, the autonomy gate passes it, the task runs locally, the result frame goes back, and both sides have a WAL audit trail. No cluster-key HMAC is added at the frame level (the Noise SecretStream is already authenticated per-connection; the peer identity is already the Noise remote_public_key, not a payload claim).

COMMIT 3 — SL-01b gossip send-path (multi-day, scope it explicitly):

This is genuinely larger. The real work: (a) a gossip send function `send_gossip_frame(stream, wal_bytes, vc, origin) -> Result<()>` that wraps WAL bytes in a GossipFrame and writes via write_framed to a dedicated gossip multiplexed channel (or a separate Hyperswarm topic), (b) a receiver that calls `GossipFrame::evaluate_acceptance` then writes WAL bytes to the local WAL writer, (c) a per-peer dedup table (SQLite or in-memory BTreeMap<PeerId, u64> of last_seen_seq), (d) the VectorClock tick/merge wiring. The primitives (gossip_wire.rs) are all correct. The transport gap is real: ~300 lines minimum. Scope it as 2-3 days, not 1. Do NOT conflate it with Commit 2 — the slave accept path proves the round-trip works and is independently shippable.

WAL CODES — exact free slots and required registrations for all three commits:
- 0xEA: EVENT_TYPE_CLUSTER_HEARTBEAT_SENT (Commit 1)
- 0xEB: EVENT_TYPE_CLUSTER_TASK_ACCEPTED (Commit 2)
- 0xEC: EVENT_TYPE_CLUSTER_TASK_REJECTED (Commit 2)
- 0xED–0xEF: reserved for gossip transport (Commit 3)

For each new constant: add to events.rs constant block, EVENT_NAME_TABLE, band assert with upper bound 0xEF (already the pattern for 0xE8/0xE9 at lines 1615-1617), and uniqueness-test array.

**Risks:**
- peeroxide's SwarmConnection does not expose independent read/write halves — the current hyperswarm.rs uses conn.peer.stream.write() and conn.peer.stream.read() as sequential calls on the same object. Adding concurrent sender + receiver requires either a Mutex over the write half or a tokio::select! pattern with exclusive stream ownership. Check peeroxide 1.3.x API before assuming split is available; if not, use a single select! loop as shown.
- The outbound heartbeat sends `tokens_per_sec: 0.0` until a real load meter is wired. This is acceptable for v1.0 (a peer correctly reports idle) but the cluster routing table sees every peer as equally idle — LeastLoaded routing becomes random. Document this explicitly; it is not theater since 0.0 is a valid, non-NaN value that passes validate_heartbeat.
- spawn_discovery_with_wal is not called in serve.rs — this means ALL the inbound WAL infrastructure is dormant in production. The serve.rs cluster section at line 1549 only has the audit-sidecar ingester. Adding the spawn_discovery_with_wal call is required for Commit 1 to be non-theater. Confirm the peeroxide SwarmConfig::with_public_bootstrap() is appropriate or whether a private bootstrap from freedom.yaml should gate the call.
- The band assertions for 0xE0-0xE7 at events.rs lines 1597-1612 still use `> 0xE7` as the upper bound. The 0xEA-0xEC constants must use `> 0xEF` as the upper bound (already the pattern for 0xE8/0xE9). Failing to update the assert will trip a compile-time OOB error — which is good, but must be planned for.
- SL-01 task-accept passes the peer's Noise public key as the subject to Gate::with_lease_snapshot. The operator's lease must be granted TO that hex key. Today the lease store uses whatever string the operator typed at `neoth lease grant`. There is no automatic bridge from 'peer I confirmed in cluster.yaml' to 'lease subject'. A small convenience command `neoth lease grant --peer <pub_key_prefix> cluster_task_accept --ttl 8h` prevents operator error.
- SL-01b gossip transport shares a Hyperswarm stream with heartbeats unless a second topic or multiplexing is added. Writing large WAL segments into the heartbeat stream would violate MAX_FRAME_BYTES=65536. Gossip frames must either be split across multiple heartbeat-band frames (complex) or use a separate peeroxide topic join. This is the largest unknown in Commit 3 and the main reason it is multi-day.

---
