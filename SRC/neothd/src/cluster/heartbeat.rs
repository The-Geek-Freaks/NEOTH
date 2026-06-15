//! R-7 heartbeat wire protocol — per Chorus chat
//! `019E4A48975F25C0BD9F8B96BC085C94` verdict.
//!
//! Both reviewers picked:
//!   Q1 encoding         CBOR
//!   Q2 framing          u32 LE length-prefixed, 64 KiB max
//!   Q3 cadence          5s baseline ± 20% jitter, on-change
//!                       push rate-limited 1/sec, unhealthy
//!                       after 3 missed intervals (~15s)
//!   Q4 versioning       protocol-version handshake on connect
//!                       (Hello frame; mismatched version
//!                       disconnects cleanly)
//!
//! Plus the required schema additions:
//!   - monotonic per-connection sequence number
//!   - separate `CapabilityUpdate` frame so the heartbeat
//!     hot path carries only volatile load metrics
//!   - cluster name hash in the handshake (HyperDHT topic
//!     alone is not sufficient as a protocol guard)
//!   - frame-level limits + NaN/Inf/negative validation
//!
//! ## Module layout
//!
//!   - [`FrameKind`] / [`WireFrame`] / body structs — the
//!     wire shape, serde-derived for ciborium.
//!   - [`encode_frame`] / [`decode_frame`] — pure CBOR
//!     round-trip without IO.
//!   - [`write_framed`] / [`read_framed`] — length-prefixed
//!     IO on top of any `AsyncRead` / `AsyncWrite`.
//!   - [`validate_heartbeat`] — rejects NaN/Inf/negative
//!     `tokens_per_sec` + bounds-checks capability lists.
//!   - [`next_jittered_interval`] — operator-tunable cadence
//!     with the Chorus-specified 5s ± 20% spread.
//!
//! The actual swarm loop (read incoming frames →
//! `validate_heartbeat` → `registry.record_heartbeat`) lives
//! in [`super::hyperswarm`]; that integration ships as a
//! follow-up once peeroxide's stream surface is wired into
//! the swarm scaffold.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Protocol identifier in the Hello frame. Hard-coded so a
/// peer running a different NEOTH protocol (Keet, channel
/// adapter, ...) on the same HyperDHT topic is detected at
/// handshake and disconnected cleanly.
pub const PROTOCOL_NAME: &str = "neoth-r7-heartbeat";

/// Wire-protocol version. Bumped when the frame schema
/// changes incompatibly. Peers with mismatched versions
/// drop the connection per Chorus Q4.
///
/// v2 (SL-00 1b): the Hello now carries a mandatory `cluster_key_proof`.
/// This is a breaking change — all nodes in a cluster must run >= v2
/// together (a v1 peer's Hello omits the proof and is rejected fail-closed).
///
/// v3 (SL-01): adds `FrameKind::TaskDelegate` + `TaskResult` (tagged-enum
/// variants). A v2 peer cannot decode the new tags (ciborium errors on an
/// unknown enum variant), so this is a breaking change — the handshake
/// version check keeps v2 and v3 nodes from pairing, so a v3 task frame never
/// reaches a v2 decoder. All cluster nodes upgrade to >= v3 together.
///
/// v4 (SL-01b): adds `FrameKind::Gossip` (WAL anti-entropy). Same breaking-tag
/// rationale — the `!=`-check in `validate_hello` keeps v3 and v4 nodes from
/// pairing, so a v4 Gossip frame never reaches a v3 decoder.
pub const PROTOCOL_VERSION: u16 = 4;

/// Frame-size hard cap. Per Codex Q2 verdict: a malformed
/// length-prefix can lead to a denial-of-memory before any
/// CBOR parsing fires; reject oversized frames at the
/// length-prefix layer.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

/// Baseline heartbeat interval. Per Codex Q3 — fixed 5s with
/// jitter is more route-friendly than pure-adaptive (which
/// goes stale exactly when an idle peer becomes relevant).
pub const HEARTBEAT_INTERVAL_MS: u64 = 5_000;

/// Per-side jitter applied to the heartbeat interval, in
/// percent. Avoids synchronized bursts across a cluster.
pub const HEARTBEAT_JITTER_PCT: u64 = 20;

/// Peers are marked unhealthy after this many milliseconds
/// without a valid heartbeat. Three missed intervals (~15s)
/// matches Codex's verdict; longer would let routing pick
/// dead peers.
pub const UNHEALTHY_AFTER_MS: u64 = 15_000;

/// Per-connection rate limit on on-change push frames. Stops
/// a noisy peer from flooding the cluster with sub-second
/// load updates.
pub const ONCHANGE_PUSH_MIN_INTERVAL_MS: u64 = 1_000;

/// Max number of capability strings in a CapabilityUpdate
/// frame. Defends against a malicious peer claiming a million
/// capabilities to OOM the routing table.
pub const MAX_CAPABILITIES: usize = 64;

/// Max length of a single capability string.
pub const MAX_CAPABILITY_STRING_LEN: usize = 64;

/// Discriminator for the four message kinds NEOTH peers
/// exchange. Bumping the schema means adding a new variant +
/// keeping the existing ones additive — CBOR + serde tolerate
/// unknown fields per the Codex verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    /// Handshake on connect. MUST be the first frame from
    /// each side; peers with mismatched protocol/version
    /// disconnect.
    Hello,
    /// Periodic load + health snapshot.
    Heartbeat,
    /// Sent on connect + when capabilities change. Reduces
    /// heartbeat hot-path payload size.
    CapabilityUpdate,
    /// Peer is leaving cleanly. Receiver drops the
    /// `PeerLoad` row immediately instead of waiting for the
    /// unhealthy timeout.
    Goodbye,
    /// SL-01: a master delegates a task (a prompt to run through
    /// the local provider) to this node. Subject to the
    /// 3-checkpoint accept gate.
    TaskDelegate,
    /// SL-01: the slave's reply to a `TaskDelegate` — the
    /// completion, a rejection reason, or an execution error.
    TaskResult,
    /// SL-01b: a WAL-gossip frame (anti-entropy). Carries a replicable WAL
    /// frame + the sender's VectorClock. Subject to the band-filter ACL.
    Gossip,
}

/// Wire envelope every frame carries. Body varies per kind;
/// shared header lets a peer log + count frames without
/// decoding the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFrame {
    pub kind: FrameKind,
    /// Monotonic per-connection sequence number. Receiver
    /// uses it for stale-frame detection (an out-of-order
    /// heartbeat sneaking through is dropped) + observability.
    pub sequence: u64,
    /// Sender's wall-clock at frame send, milliseconds since
    /// unix epoch. Receiver compares against local clock for
    /// staleness — see [`UNHEALTHY_AFTER_MS`].
    pub sent_unix_ms: u64,
    /// Sender's UUID v7 peer id. Same value across every
    /// frame from a given peer.
    pub peer_id: String,
    /// Kind-specific body, CBOR-encoded as a sibling field.
    pub body: FrameBody,
}

/// Per-kind body shapes. Serialised as a tagged enum so a
/// receiver running an OLDER protocol can still parse the
/// envelope + report `unknown body kind` instead of
/// silently mis-routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameBody {
    Hello(HelloBody),
    Heartbeat(HeartbeatBody),
    CapabilityUpdate(CapabilityUpdateBody),
    Goodbye(GoodbyeBody),
    TaskDelegate(TaskDelegateBody),
    TaskResult(TaskResultBody),
    Gossip(super::gossip_wire::GossipFrame),
}

/// Hello body — sent first on each connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloBody {
    /// Pinned to [`PROTOCOL_NAME`].
    pub protocol: String,
    /// Pinned to [`PROTOCOL_VERSION`].
    pub version: u16,
    /// Hash of the cluster name. Per Codex Q4 — HyperDHT
    /// topic alone isn't sufficient as a protocol guard; the
    /// cluster-name hash binds the connection to a specific
    /// operator-named cluster.
    pub cluster_name_hash: [u8; 32],
    /// Capabilities are sent once in the Hello + then only
    /// via `CapabilityUpdate` frames.
    pub capabilities: Vec<String>,
    /// Bump independently from PROTOCOL_VERSION when the
    /// capability vocabulary changes (e.g. a new
    /// `webhook_listener` capability lands). Receiver caches
    /// against this so duplicate Hellos with the same
    /// `capabilities_schema_version` skip re-validation.
    pub capabilities_schema_version: u32,
    /// SL-00(1b) — per-session cluster authorization proof: HMAC-SHA256 over
    /// the two Noise static pubkeys (signer first) keyed by the shared
    /// `cluster_key` (see `cluster::peer_auth`). Proves the peer holds the
    /// cluster passphrase WITHOUT the public-name-only weakness. `Option` for
    /// CBOR forward-compat, but the verifier treats `None` as a hard
    /// rejection (fail-closed): a peer that omits it is unauthorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_key_proof: Option<[u8; 32]>,
}

/// Heartbeat body — volatile load metrics only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatBody {
    /// Current outbound token rate. NaN/Inf/negative values
    /// are rejected by [`validate_heartbeat`].
    pub tokens_per_sec: f64,
    /// In-flight provider requests count. Routing prefers
    /// peers with lower inflight regardless of TPS.
    pub inflight_requests: u32,
    /// Peer's own healthy-vs-degraded self-assessment. The
    /// routing layer ALSO honours the local staleness check
    /// (a peer claiming `healthy: true` past the staleness
    /// window is still marked unhealthy locally).
    pub healthy: bool,
    /// Hash over the most-recent capability list. When this
    /// changes, the receiver expects a `CapabilityUpdate`
    /// frame to follow within ONCHANGE_PUSH_MIN_INTERVAL_MS;
    /// otherwise re-request via `RequestCapabilities` (v0.2
    /// addition).
    pub capabilities_hash: [u8; 32],
}

/// CapabilityUpdate body — full list of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUpdateBody {
    pub capabilities: Vec<String>,
}

/// Goodbye body — optional reason for the disconnect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoodbyeBody {
    pub reason: Option<String>,
}

/// SL-01 maximum delegated-prompt size (bytes). A master cannot force the slave
/// to run a maximal-context inference; 8 KiB is generous for a real delegated
/// task and well under [`MAX_FRAME_BYTES`]. Validated BEFORE the accept gate.
pub const MAX_TASK_PROMPT_BYTES: usize = 8 * 1024;
/// SL-01 maximum `task_id` / `model_hint` string length (bytes).
pub const MAX_TASK_ID_BYTES: usize = 64;

/// SL-01 TaskDelegate body — a master delegating a prompt to this node.
/// The requester identity is NEVER carried here: it is the authenticated Noise
/// static key (`remote_pk_hex`) of the connection. Bounds are enforced by
/// [`validate_task_delegate`] before the accept gate spends any work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDelegateBody {
    /// Master-generated correlation id (UUID). Echoed back in the result.
    pub task_id: String,
    /// The prompt to run through the slave's local provider.
    pub prompt: String,
    /// Preferred model id. ADVISORY ONLY in this lane — the slave runs its own
    /// configured provider and ignores an unknown hint (no confused-deputy:
    /// a master can't force the slave to call an arbitrary/expensive model).
    /// Capability-aware routing is v1.0 hardening.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<String>,
}

/// SL-01 result status. `Rejected` = the accept gate refused (with a reason
/// the master can act on); `Failed` = accepted but execution errored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum TaskResultStatus {
    Completed,
    Rejected { reason: String },
    Failed { error: String },
}

/// SL-01 TaskResult body — the slave's reply to a delegated task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultBody {
    /// Echoes [`TaskDelegateBody::task_id`] for correlation on the master.
    pub task_id: String,
    pub status: TaskResultStatus,
    /// The completion text — present only on `Completed`. The slave truncates
    /// to keep the encoded frame under [`MAX_FRAME_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Which provider the slave actually ran (observability for the master).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
}

/// Validate an inbound [`TaskDelegateBody`] BEFORE the accept gate. Fail-closed
/// on oversized / empty input so a malicious peer can't exhaust resources or
/// pollute the WAL with a giant `task_id`. A peer need not be paired for its
/// malformed frame to be rejected.
pub fn validate_task_delegate(body: &TaskDelegateBody) -> Result<()> {
    if body.task_id.is_empty() {
        anyhow::bail!("task_delegate: empty task_id");
    }
    if body.task_id.len() > MAX_TASK_ID_BYTES {
        anyhow::bail!(
            "task_delegate: task_id {} bytes exceeds cap {MAX_TASK_ID_BYTES}",
            body.task_id.len()
        );
    }
    if body.prompt.is_empty() {
        anyhow::bail!("task_delegate: empty prompt");
    }
    if body.prompt.len() > MAX_TASK_PROMPT_BYTES {
        anyhow::bail!(
            "task_delegate: prompt {} bytes exceeds cap {MAX_TASK_PROMPT_BYTES}",
            body.prompt.len()
        );
    }
    if let Some(hint) = &body.model_hint {
        if hint.len() > MAX_TASK_ID_BYTES {
            anyhow::bail!(
                "task_delegate: model_hint {} bytes exceeds cap {MAX_TASK_ID_BYTES}",
                hint.len()
            );
        }
    }
    Ok(())
}

/// CBOR-encode a wire frame. Pure — no IO, no allocations
/// beyond the returned Vec.
pub fn encode_frame(frame: &WireFrame) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    ciborium::into_writer(frame, &mut out).context("cbor encode WireFrame")?;
    Ok(out)
}

/// CBOR-decode a wire frame. Pure — caller is responsible for
/// validating semantic invariants via [`validate_heartbeat`]
/// when the body is Heartbeat.
pub fn decode_frame(bytes: &[u8]) -> Result<WireFrame> {
    let frame: WireFrame = ciborium::from_reader(bytes).context("cbor decode WireFrame")?;
    Ok(frame)
}

/// Write a length-prefixed CBOR frame to any `AsyncWrite`.
/// Prefix is u32 LE; payload length is rejected when it
/// exceeds [`MAX_FRAME_BYTES`].
pub async fn write_framed<W: AsyncWriteExt + Unpin>(sink: &mut W, frame: &WireFrame) -> Result<()> {
    let bytes = encode_frame(frame)?;
    let len = u32::try_from(bytes.len()).context("frame too large for u32 length-prefix")?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("frame size {len} exceeds MAX_FRAME_BYTES {MAX_FRAME_BYTES}");
    }
    sink.write_all(&len.to_le_bytes())
        .await
        .context("write len-prefix")?;
    sink.write_all(&bytes).await.context("write frame body")?;
    sink.flush().await.context("flush frame")?;
    Ok(())
}

/// Read one length-prefixed CBOR frame from any `AsyncRead`.
/// Length-prefix is u32 LE; oversized frames are rejected
/// before allocating the read buffer (defends against a
/// hostile peer claiming a 4 GiB heartbeat).
pub async fn read_framed<R: AsyncReadExt + Unpin>(source: &mut R) -> Result<WireFrame> {
    let mut len_buf = [0u8; 4];
    source
        .read_exact(&mut len_buf)
        .await
        .context("read frame len-prefix")?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("incoming frame size {len} exceeds MAX_FRAME_BYTES {MAX_FRAME_BYTES}");
    }
    let mut buf = vec![0u8; len as usize];
    source
        .read_exact(&mut buf)
        .await
        .context("read frame body")?;
    decode_frame(&buf)
}

/// Reject a Heartbeat body whose load values are unsafe to
/// feed into the routing math. Per Codex verdict — NaN/Inf
/// from a remote peer would silently corrupt the LeastLoaded
/// pick; reject at the wire boundary.
pub fn validate_heartbeat(body: &HeartbeatBody) -> Result<()> {
    if !body.tokens_per_sec.is_finite() {
        anyhow::bail!(
            "heartbeat tokens_per_sec is not finite: {}",
            body.tokens_per_sec
        );
    }
    if body.tokens_per_sec.is_sign_negative() {
        anyhow::bail!(
            "heartbeat tokens_per_sec is negative: {}",
            body.tokens_per_sec
        );
    }
    // Sanity cap: a single peer reporting > 1 million tokens/sec
    // is almost certainly buggy or hostile.
    if body.tokens_per_sec > 1_000_000.0 {
        anyhow::bail!(
            "heartbeat tokens_per_sec exceeds sanity cap: {}",
            body.tokens_per_sec
        );
    }
    Ok(())
}

/// Reject a CapabilityUpdate that exceeds the per-frame
/// budget. Defends against a peer claiming a million
/// capabilities.
pub fn validate_capabilities(body: &CapabilityUpdateBody) -> Result<()> {
    if body.capabilities.len() > MAX_CAPABILITIES {
        anyhow::bail!(
            "capability list len {} exceeds MAX_CAPABILITIES {MAX_CAPABILITIES}",
            body.capabilities.len()
        );
    }
    for (i, cap) in body.capabilities.iter().enumerate() {
        if cap.len() > MAX_CAPABILITY_STRING_LEN {
            anyhow::bail!(
                "capability[{i}] len {} exceeds MAX_CAPABILITY_STRING_LEN {MAX_CAPABILITY_STRING_LEN}",
                cap.len()
            );
        }
    }
    Ok(())
}

/// Reject a Hello frame whose protocol/version don't match
/// ours. Receiver disconnects cleanly per Q4.
pub fn validate_hello(body: &HelloBody) -> Result<()> {
    if body.protocol != PROTOCOL_NAME {
        anyhow::bail!(
            "hello protocol {:?} does not match expected {PROTOCOL_NAME:?}",
            body.protocol
        );
    }
    if body.version != PROTOCOL_VERSION {
        anyhow::bail!(
            "hello version {} does not match expected {PROTOCOL_VERSION}",
            body.version
        );
    }
    if body.capabilities.len() > MAX_CAPABILITIES {
        anyhow::bail!(
            "hello capability list len {} exceeds MAX_CAPABILITIES {MAX_CAPABILITIES}",
            body.capabilities.len()
        );
    }
    Ok(())
}

/// Return the next jittered heartbeat interval. Pure
/// function over a caller-supplied RNG so tests can pin
/// the output deterministically. Production callers pass
/// `rand::thread_rng()`.
///
/// Mean is [`HEARTBEAT_INTERVAL_MS`]; spread is ± `HEARTBEAT_JITTER_PCT`
/// percent of that.
pub fn next_jittered_interval(rng: &mut impl rand::Rng) -> Duration {
    let base = HEARTBEAT_INTERVAL_MS as i64;
    let jitter_range = base * HEARTBEAT_JITTER_PCT as i64 / 100;
    let offset = rng.random_range(-jitter_range..=jitter_range);
    let interval = base.saturating_add(offset).max(1) as u64;
    Duration::from_millis(interval)
}

/// Derive a 32-byte capabilities hash from a list. Used by
/// the Heartbeat body's `capabilities_hash` field so receiver
/// can detect "this peer's capabilities changed" without the
/// full list every heartbeat.
pub fn hash_capabilities(caps: &[String]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for cap in caps {
        hasher.update(cap.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> WireFrame {
        WireFrame {
            kind: FrameKind::Hello,
            sequence: 0,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: "peer-1".to_string(),
            body: FrameBody::Hello(HelloBody {
                protocol: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION,
                cluster_name_hash: [0xAB; 32],
                capabilities: vec!["claude_cli".into(), "openai_compat".into()],
                capabilities_schema_version: 1,
                cluster_key_proof: None,
            }),
        }
    }

    fn sample_heartbeat() -> WireFrame {
        WireFrame {
            kind: FrameKind::Heartbeat,
            sequence: 42,
            sent_unix_ms: 1_700_000_005_000,
            peer_id: "peer-1".to_string(),
            body: FrameBody::Heartbeat(HeartbeatBody {
                tokens_per_sec: 12.5,
                inflight_requests: 3,
                healthy: true,
                capabilities_hash: [0xCD; 32],
            }),
        }
    }

    #[test]
    fn encode_decode_round_trips_hello() {
        let frame = sample_hello();
        let bytes = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&bytes).unwrap();
        assert_eq!(decoded.kind, FrameKind::Hello);
        assert_eq!(decoded.peer_id, "peer-1");
        match decoded.body {
            FrameBody::Hello(b) => {
                assert_eq!(b.protocol, PROTOCOL_NAME);
                assert_eq!(b.version, PROTOCOL_VERSION);
                assert_eq!(b.capabilities, vec!["claude_cli", "openai_compat"]);
            }
            other => panic!("expected Hello body, got {other:?}"),
        }
    }

    #[test]
    fn encode_decode_round_trips_heartbeat() {
        let frame = sample_heartbeat();
        let bytes = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&bytes).unwrap();
        assert_eq!(decoded.sequence, 42);
        match decoded.body {
            FrameBody::Heartbeat(b) => {
                assert_eq!(b.tokens_per_sec, 12.5);
                assert_eq!(b.inflight_requests, 3);
                assert!(b.healthy);
            }
            other => panic!("expected Heartbeat body, got {other:?}"),
        }
    }

    #[test]
    fn task_delegate_round_trips_and_validates() {
        let frame = WireFrame {
            kind: FrameKind::TaskDelegate,
            sequence: 7,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: "master-1".into(),
            body: FrameBody::TaskDelegate(TaskDelegateBody {
                task_id: "task-abc".into(),
                prompt: "summarize this".into(),
                model_hint: Some("qwen3".into()),
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        match decode_frame(&bytes).unwrap().body {
            FrameBody::TaskDelegate(b) => {
                assert_eq!(b.task_id, "task-abc");
                assert_eq!(b.prompt, "summarize this");
                validate_task_delegate(&b).expect("well-formed delegate validates");
            }
            other => panic!("expected TaskDelegate, got {other:?}"),
        }
    }

    #[test]
    fn task_result_round_trips_with_status_tag() {
        let frame = WireFrame {
            kind: FrameKind::TaskResult,
            sequence: 8,
            sent_unix_ms: 1_700_000_000_001,
            peer_id: "slave-1".into(),
            body: FrameBody::TaskResult(TaskResultBody {
                task_id: "task-abc".into(),
                status: TaskResultStatus::Rejected {
                    reason: "no_active_lease".into(),
                },
                result: None,
                provider_name: None,
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        match decode_frame(&bytes).unwrap().body {
            FrameBody::TaskResult(b) => {
                assert_eq!(b.task_id, "task-abc");
                assert_eq!(
                    b.status,
                    TaskResultStatus::Rejected {
                        reason: "no_active_lease".into()
                    }
                );
            }
            other => panic!("expected TaskResult, got {other:?}"),
        }
    }

    #[test]
    fn gossip_frame_round_trips_on_the_wire() {
        use super::super::gossip::GossipTag;
        use super::super::gossip_wire::{GossipFrame, VectorClock};
        use super::super::PeerPubkey;
        let mut vc = VectorClock::new();
        vc.tick(&PeerPubkey::new("node-a"));
        let frame = WireFrame {
            kind: FrameKind::Gossip,
            sequence: 11,
            sent_unix_ms: 1_700_000_000_002,
            peer_id: "node-a".into(),
            body: FrameBody::Gossip(GossipFrame {
                vector_clock: vc,
                origin: PeerPubkey::new("node-a"),
                event_seq: 3,
                timestamp_unix: 1_700_000_000,
                tag: GossipTag::Replicate,
                payload: vec![0xE0, 0x00, 0xE0],
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        match decode_frame(&bytes).unwrap().body {
            FrameBody::Gossip(g) => {
                assert_eq!(g.event_seq, 3);
                assert_eq!(g.origin, PeerPubkey::new("node-a"));
                assert_eq!(g.tag, GossipTag::Replicate);
            }
            other => panic!("expected Gossip, got {other:?}"),
        }
    }

    #[test]
    fn validate_task_delegate_enforces_bounds() {
        let ok = TaskDelegateBody {
            task_id: "t".into(),
            prompt: "p".into(),
            model_hint: None,
        };
        assert!(validate_task_delegate(&ok).is_ok());

        // Empty task_id / empty prompt rejected.
        assert!(
            validate_task_delegate(&TaskDelegateBody {
                task_id: String::new(),
                prompt: "p".into(),
                model_hint: None,
            })
            .is_err()
        );
        assert!(
            validate_task_delegate(&TaskDelegateBody {
                task_id: "t".into(),
                prompt: String::new(),
                model_hint: None,
            })
            .is_err()
        );

        // Oversized prompt rejected (resource-exhaustion guard).
        assert!(
            validate_task_delegate(&TaskDelegateBody {
                task_id: "t".into(),
                prompt: "x".repeat(MAX_TASK_PROMPT_BYTES + 1),
                model_hint: None,
            })
            .is_err(),
            "prompt over {MAX_TASK_PROMPT_BYTES} bytes must be rejected"
        );

        // Oversized task_id + model_hint rejected.
        assert!(
            validate_task_delegate(&TaskDelegateBody {
                task_id: "x".repeat(MAX_TASK_ID_BYTES + 1),
                prompt: "p".into(),
                model_hint: None,
            })
            .is_err()
        );
        assert!(
            validate_task_delegate(&TaskDelegateBody {
                task_id: "t".into(),
                prompt: "p".into(),
                model_hint: Some("x".repeat(MAX_TASK_ID_BYTES + 1)),
            })
            .is_err()
        );
    }

    #[test]
    fn encode_produces_compact_cbor_smaller_than_json() {
        // Sanity check on the Q1 choice — CBOR really is more
        // compact than the equivalent JSON for our shape.
        let frame = sample_heartbeat();
        let cbor = encode_frame(&frame).unwrap();
        let json = serde_json::to_vec(&frame).unwrap();
        assert!(
            cbor.len() < json.len(),
            "CBOR {} bytes must beat JSON {} bytes for the same frame",
            cbor.len(),
            json.len()
        );
    }

    #[tokio::test]
    async fn write_framed_then_read_framed_round_trip() {
        let frame = sample_heartbeat();
        let mut buf: Vec<u8> = Vec::new();
        write_framed(&mut buf, &frame).await.unwrap();
        // First 4 bytes are the u32 LE length prefix.
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(len + 4, buf.len());

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_framed(&mut cursor).await.unwrap();
        assert_eq!(decoded.sequence, 42);
    }

    #[tokio::test]
    async fn read_framed_rejects_oversized_length_prefix() {
        // Craft a buffer claiming a 1 GiB payload — must
        // bail at the length check, NOT allocate.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(1_073_741_824u32).to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_framed(&mut cursor).await.unwrap_err().to_string();
        assert!(err.contains("MAX_FRAME_BYTES"), "diagnostic: {err}");
    }

    #[test]
    fn validate_heartbeat_rejects_nan_inf_negative() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -0.001] {
            let body = HeartbeatBody {
                tokens_per_sec: bad,
                inflight_requests: 0,
                healthy: true,
                capabilities_hash: [0; 32],
            };
            assert!(
                validate_heartbeat(&body).is_err(),
                "must reject tokens_per_sec={bad}"
            );
        }
    }

    #[test]
    fn validate_heartbeat_rejects_absurd_tps_value() {
        let body = HeartbeatBody {
            tokens_per_sec: 9_999_999.0,
            inflight_requests: 0,
            healthy: true,
            capabilities_hash: [0; 32],
        };
        assert!(validate_heartbeat(&body).is_err());
    }

    #[test]
    fn validate_heartbeat_accepts_realistic_values() {
        let body = HeartbeatBody {
            tokens_per_sec: 8.5,
            inflight_requests: 2,
            healthy: true,
            capabilities_hash: [0; 32],
        };
        assert!(validate_heartbeat(&body).is_ok());
        // Zero TPS is fine — peer is idle, not broken.
        let zero = HeartbeatBody {
            tokens_per_sec: 0.0,
            inflight_requests: 0,
            healthy: true,
            capabilities_hash: [0; 32],
        };
        assert!(validate_heartbeat(&zero).is_ok());
    }

    #[test]
    fn validate_capabilities_caps_count_and_string_len() {
        let too_many = CapabilityUpdateBody {
            capabilities: (0..(MAX_CAPABILITIES + 1))
                .map(|i| format!("c{i}"))
                .collect(),
        };
        assert!(validate_capabilities(&too_many).is_err());

        let too_long = CapabilityUpdateBody {
            capabilities: vec!["x".repeat(MAX_CAPABILITY_STRING_LEN + 1)],
        };
        assert!(validate_capabilities(&too_long).is_err());

        let ok = CapabilityUpdateBody {
            capabilities: vec!["claude_cli".into(), "local_qwen".into()],
        };
        assert!(validate_capabilities(&ok).is_ok());
    }

    #[test]
    fn validate_hello_rejects_wrong_protocol() {
        let bad = HelloBody {
            protocol: "wrong-protocol".to_string(),
            version: PROTOCOL_VERSION,
            cluster_name_hash: [0; 32],
            capabilities: vec![],
            capabilities_schema_version: 1,
            cluster_key_proof: None,
        };
        assert!(validate_hello(&bad).is_err());
    }

    #[test]
    fn validate_hello_rejects_wrong_version() {
        let bad = HelloBody {
            protocol: PROTOCOL_NAME.to_string(),
            version: PROTOCOL_VERSION + 1,
            cluster_name_hash: [0; 32],
            capabilities: vec![],
            capabilities_schema_version: 1,
            cluster_key_proof: None,
        };
        assert!(validate_hello(&bad).is_err());
    }

    #[test]
    fn validate_hello_accepts_canonical_shape() {
        let good = HelloBody {
            protocol: PROTOCOL_NAME.to_string(),
            version: PROTOCOL_VERSION,
            cluster_name_hash: [0xFF; 32],
            capabilities: vec!["claude_cli".into()],
            capabilities_schema_version: 1,
            cluster_key_proof: None,
        };
        assert!(validate_hello(&good).is_ok());
    }

    #[test]
    fn hello_cluster_key_proof_round_trips_on_the_wire() {
        // SL-00(1b): the proof must survive encode→decode so the verifier sees it.
        let frame = WireFrame {
            kind: FrameKind::Hello,
            sequence: 0,
            sent_unix_ms: 1,
            peer_id: "p".into(),
            body: FrameBody::Hello(HelloBody {
                protocol: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION,
                cluster_name_hash: [7; 32],
                capabilities: vec![],
                capabilities_schema_version: 1,
                cluster_key_proof: Some([0xAB; 32]),
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        let back = decode_frame(&bytes).unwrap();
        match back.body {
            FrameBody::Hello(b) => assert_eq!(b.cluster_key_proof, Some([0xAB; 32])),
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn next_jittered_interval_stays_within_jitter_band() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let base = HEARTBEAT_INTERVAL_MS as i64;
        let max_offset = base * HEARTBEAT_JITTER_PCT as i64 / 100;
        let min_allowed = (base - max_offset) as u64;
        let max_allowed = (base + max_offset) as u64;
        for _ in 0..100 {
            let interval = next_jittered_interval(&mut rng);
            let ms = interval.as_millis() as u64;
            assert!(
                ms >= min_allowed && ms <= max_allowed,
                "jittered interval {ms}ms outside [{min_allowed}, {max_allowed}]"
            );
        }
    }

    #[test]
    fn hash_capabilities_is_deterministic_and_distinguishes() {
        let a = hash_capabilities(&["claude_cli".into(), "openai".into()]);
        let b = hash_capabilities(&["claude_cli".into(), "openai".into()]);
        assert_eq!(a, b);

        let c = hash_capabilities(&["claude_cli".into()]);
        assert_ne!(a, c);

        // Order matters — different lists must hash distinctly.
        let d = hash_capabilities(&["openai".into(), "claude_cli".into()]);
        assert_ne!(a, d);
    }

    #[test]
    fn frame_kind_serializes_as_snake_case() {
        // Pin the wire form — operator-facing audit greps
        // depend on these strings staying stable.
        let bytes = encode_frame(&sample_hello()).unwrap();
        let decoded = decode_frame(&bytes).unwrap();
        assert_eq!(decoded.kind, FrameKind::Hello);
        // Round-trip via serde_json to verify the snake_case
        // rename is applied (CBOR doesn't surface field names
        // for grep but JSON does).
        let json = serde_json::to_string(&decoded.kind).unwrap();
        assert_eq!(json, r#""hello""#);
    }

    #[test]
    fn constants_match_chorus_verdict() {
        // Belt-and-braces pin: any future drift on these
        // values is intentional + needs a Chorus re-review.
        assert_eq!(PROTOCOL_NAME, "neoth-r7-heartbeat");
        // v2: SL-00(1b) added the mandatory cluster_key_proof to the Hello.
        assert_eq!(PROTOCOL_VERSION, 4);
        assert_eq!(MAX_FRAME_BYTES, 64 * 1024);
        assert_eq!(HEARTBEAT_INTERVAL_MS, 5_000);
        assert_eq!(HEARTBEAT_JITTER_PCT, 20);
        assert_eq!(UNHEALTHY_AFTER_MS, 15_000);
        assert_eq!(ONCHANGE_PUSH_MIN_INTERVAL_MS, 1_000);
        assert_eq!(MAX_CAPABILITIES, 64);
    }
}
