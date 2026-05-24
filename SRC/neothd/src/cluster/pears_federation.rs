//! Cluster C-2 (Session 21, 2026-05-23) — WAL federation trait for the
//! Pears-transport cluster.
//!
//! Each peer ships its sealed WAL segments to the cluster orchestrator
//! (elected via [`super::pears_election`]) so an operator-private
//! cross-node audit trail builds up. Default impl returns `Deferred`
//! until operator-side K-3.5 pairing has been verified end-to-end
//! against a live `pear` runtime — the wire shape of segment shipping
//! isn't finalised until the K-2b PearsBridge round-trip is proven.
//!
//! ## Why a trait
//!
//! The cluster work has two ship modes in mind: Pears-transport (this
//! module's `PearsWalFederator`) and a future SaaS-relay path the
//! operator can opt into for cross-VPC peer sets. Both implement the
//! same `WalFederator` trait so callers don't care which transport
//! lands segments on the orchestrator.

use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;

/// Shipped segment summary — the data a remote peer learns about one
/// local WAL segment. The bytes themselves are streamed separately;
/// this struct is the metadata envelope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShippedSegment {
    /// Origin peer pubkey. Lets the orchestrator namespace stored
    /// segments under `~/.neoth/cluster/<pubkey>/` without cross-peer
    /// id collisions.
    pub origin_pubkey: String,
    /// Sequence number from the origin peer's `WalWriter`.
    pub segment_seq: u64,
    /// Total segment byte length (informational; the orchestrator
    /// chunks the shipping into HTTP-friendly pieces internally).
    pub segment_bytes: u64,
    /// Origin peer's monotonic clock at segment seal. Helps the
    /// orchestrator order segments from peers that disagree on
    /// wall-clock.
    pub origin_sealed_unix_ts: u64,
}

/// Federation transport. Concrete impls hand sealed WAL segments to the
/// orchestrator. Errors are typed enough to let callers distinguish
/// "transport deferred" from "transport tried + failed".
#[async_trait]
pub trait WalFederator: Send + Sync {
    /// Ship a single sealed segment. Returns the orchestrator's ACK
    /// (segment_seq + sha256 of received bytes) or an error.
    async fn ship_segment(
        &self,
        meta: ShippedSegment,
        segment_path: PathBuf,
    ) -> Result<FederationAck, FederationError>;
}

/// Orchestrator-side ACK shape. Lets the origin peer verify that the
/// orchestrator received the exact bytes (sha256 match).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FederationAck {
    pub origin_pubkey: String,
    pub segment_seq: u64,
    pub received_sha256_hex: String,
}

/// Typed federation errors. `Deferred` is the v0.1 scaffold state —
/// callers MUST handle it distinct from `Transport` so retry-loops
/// don't pound a transport that hasn't shipped yet.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    /// Implementation deliberately not wired yet. Callers stop
    /// retrying when they see this — operator action is needed
    /// (verify K-3.5 pairing + flip `freedom.yaml::cluster.transport`).
    #[error("WAL federation deferred — {0}")]
    Deferred(String),
    /// Transport-layer failure (HTTP error, bridge offline, etc).
    /// Callers may retry with backoff.
    #[error("WAL federation transport error — {0}")]
    Transport(String),
    /// Orchestrator-side rejection (auth, schema mismatch, etc).
    /// Callers should not retry without operator review.
    #[error("WAL federation rejected by orchestrator — {0}")]
    Rejected(String),
}

/// Default `WalFederator` impl for the Pears transport. Per the
/// Session 21 agent panel verdict, this stays a stub until live `pear`
/// validation closes the K-3.5 → K-2b round-trip — emitting `Deferred`
/// so any caller wired in early gets a clear "wait" signal instead of
/// silently succeeding.
pub struct PearsWalFederator {
    /// Operator-facing reason printed in the Deferred error. Lets
    /// neoth doctor surface the exact "what's missing" line.
    pub deferred_reason: String,
}

impl Default for PearsWalFederator {
    fn default() -> Self {
        Self {
            deferred_reason:
                "Pears WAL federation not yet validated against live `pear` runtime. \
                 Verify K-3.5 pairing + K-2b post_message round-trip first."
                    .to_string(),
        }
    }
}

#[async_trait]
impl WalFederator for PearsWalFederator {
    async fn ship_segment(
        &self,
        _meta: ShippedSegment,
        _segment_path: PathBuf,
    ) -> Result<FederationAck, FederationError> {
        Err(FederationError::Deferred(self.deferred_reason.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_segment_round_trips_through_json() {
        let s = ShippedSegment {
            origin_pubkey: "abc123".into(),
            segment_seq: 42,
            segment_bytes: 4096,
            origin_sealed_unix_ts: 1_700_000_000,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ShippedSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn federation_ack_round_trips_through_json() {
        let a = FederationAck {
            origin_pubkey: "abc123".into(),
            segment_seq: 42,
            received_sha256_hex: "deadbeef".repeat(8),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: FederationAck = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[tokio::test]
    async fn pears_wal_federator_default_returns_deferred_error() {
        // C-2 v0.1 contract pin: the default impl MUST return Deferred,
        // not silently succeed. Callers wiring in early shouldn't be
        // tricked into thinking shipping landed.
        let fed = PearsWalFederator::default();
        let meta = ShippedSegment {
            origin_pubkey: "alex".into(),
            segment_seq: 1,
            segment_bytes: 100,
            origin_sealed_unix_ts: 1000,
        };
        let result = fed.ship_segment(meta, PathBuf::from("/tmp/x.wal")).await;
        let err = result.unwrap_err();
        assert!(matches!(err, FederationError::Deferred(_)));
        let msg = format!("{err}");
        assert!(msg.contains("not yet validated against live `pear`"));
    }

    #[tokio::test]
    async fn pears_wal_federator_carries_custom_deferred_reason() {
        // Operator-doctor diagnostic surface: PearsWalFederator can
        // carry a more specific reason string the operator's
        // diagnostic page renders.
        let fed = PearsWalFederator {
            deferred_reason: "cluster.transport currently disabled".into(),
        };
        let meta = ShippedSegment {
            origin_pubkey: "alex".into(),
            segment_seq: 1,
            segment_bytes: 100,
            origin_sealed_unix_ts: 1000,
        };
        let err = fed
            .ship_segment(meta, PathBuf::from("/tmp/x.wal"))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("cluster.transport currently disabled"));
    }
}
