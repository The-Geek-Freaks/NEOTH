//! C-5 — typed payload shapes for cluster lifecycle WAL events
//! 0xE8 `CLUSTER_ROLE_CHANGED` + 0xE9 `CLUSTER_REQUEST_FORWARDED`.
//!
//! Pure-fn module: structs + serde + helper that yields the JSON
//! byte vec the WAL writer consumes. No transport wiring here —
//! that piece (C-1..C-4) is gated on the K-1 Hyperswarm path
//! decision. The payload shape is fixed regardless of which
//! transport implementation ships, so C-5 lands independently.

use serde::{Deserialize, Serialize};

/// Reason the local node's cluster role changed. Pinned exhaustively
/// — a future addition needs an operator-visible name in
/// `neoth cluster status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleChangeReason {
    /// Election round picked this node as orchestrator.
    Election,
    /// Operator forced the role via `neoth cluster role <new>`.
    Manual,
    /// Previous orchestrator went away (heartbeat missed).
    PeerLoss,
}

impl RoleChangeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Election => "election",
            Self::Manual => "manual",
            Self::PeerLoss => "peer_loss",
        }
    }
}

/// Payload for [`crate::wal::events::EVENT_TYPE_CLUSTER_ROLE_CHANGED`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRoleChangedPayload {
    /// Previous role string (e.g. `"follower"`).
    pub old_role: String,
    /// New role string (e.g. `"orchestrator"`).
    pub new_role: String,
    pub reason: RoleChangeReason,
    /// Unix epoch seconds at the role transition.
    pub ts_unix: i64,
}

impl ClusterRoleChangedPayload {
    pub fn new(
        old_role: impl Into<String>,
        new_role: impl Into<String>,
        reason: RoleChangeReason,
        ts_unix: i64,
    ) -> Self {
        Self {
            old_role: old_role.into(),
            new_role: new_role.into(),
            reason,
            ts_unix,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // GOLD-SEC-25 / A-48: fail loud rather than write an EMPTY payload
        // into the WAL on a serialization failure. POD struct (no floats),
        // so serde_json is infallible here.
        serde_json::to_vec(self).expect("cluster WAL payload is POD; serde_json serialization is infallible")
    }
}

/// Reason a request was forwarded to a peer. Pinned exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardReason {
    /// Peer holds a model/skill/capability the local node lacks.
    Capability,
    /// Local node is overloaded; peer has spare cycles.
    Load,
    /// Conversation already pinned to peer (sticky routing).
    Affinity,
    /// Primary provider failed; peer is the failover.
    Fallback,
}

impl ForwardReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Load => "load",
            Self::Affinity => "affinity",
            Self::Fallback => "fallback",
        }
    }
}

/// Payload for
/// [`crate::wal::events::EVENT_TYPE_CLUSTER_REQUEST_FORWARDED`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRequestForwardedPayload {
    /// Internal request id (matches the corresponding PROVIDER_REQUEST
    /// 0x20 event so replay anchors the routing decision).
    pub request_id: String,
    /// Hex pubkey of the peer the request landed at.
    pub target_peer_pubkey: String,
    pub reason: ForwardReason,
    pub ts_unix: i64,
}

impl ClusterRequestForwardedPayload {
    pub fn new(
        request_id: impl Into<String>,
        target_peer_pubkey: impl Into<String>,
        reason: ForwardReason,
        ts_unix: i64,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            target_peer_pubkey: target_peer_pubkey.into(),
            reason,
            ts_unix,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // GOLD-SEC-25 / A-48: fail loud rather than write an EMPTY payload
        // into the WAL on a serialization failure. POD struct (no floats),
        // so serde_json is infallible here.
        serde_json::to_vec(self).expect("cluster WAL payload is POD; serde_json serialization is infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RoleChangeReason ────────────────────────────────────────

    #[test]
    fn role_change_reason_as_str_pinned() {
        assert_eq!(RoleChangeReason::Election.as_str(), "election");
        assert_eq!(RoleChangeReason::Manual.as_str(), "manual");
        assert_eq!(RoleChangeReason::PeerLoss.as_str(), "peer_loss");
    }

    #[test]
    fn role_change_reason_serialises_lowercase_kebab() {
        let s = serde_json::to_string(&RoleChangeReason::PeerLoss).unwrap();
        assert_eq!(s, "\"peer_loss\"");
    }

    // ── ClusterRoleChangedPayload ───────────────────────────────

    #[test]
    fn role_changed_constructor_stores_inputs() {
        let p = ClusterRoleChangedPayload::new(
            "follower",
            "orchestrator",
            RoleChangeReason::Election,
            1_700_000_000,
        );
        assert_eq!(p.old_role, "follower");
        assert_eq!(p.new_role, "orchestrator");
        assert_eq!(p.reason, RoleChangeReason::Election);
        assert_eq!(p.ts_unix, 1_700_000_000);
    }

    #[test]
    fn role_changed_to_bytes_emits_valid_json_with_required_fields() {
        let p = ClusterRoleChangedPayload::new(
            "orchestrator",
            "passive",
            RoleChangeReason::Manual,
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_slice(&p.to_bytes()).unwrap();
        assert_eq!(v["old_role"], "orchestrator");
        assert_eq!(v["new_role"], "passive");
        assert_eq!(v["reason"], "manual");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn role_changed_serde_round_trips() {
        let original = ClusterRoleChangedPayload::new(
            "follower",
            "orchestrator",
            RoleChangeReason::PeerLoss,
            42,
        );
        let bytes = original.to_bytes();
        let back: ClusterRoleChangedPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, original);
    }

    // ── ForwardReason ───────────────────────────────────────────

    #[test]
    fn forward_reason_as_str_pinned() {
        assert_eq!(ForwardReason::Capability.as_str(), "capability");
        assert_eq!(ForwardReason::Load.as_str(), "load");
        assert_eq!(ForwardReason::Affinity.as_str(), "affinity");
        assert_eq!(ForwardReason::Fallback.as_str(), "fallback");
    }

    #[test]
    fn forward_reason_serialises_lowercase() {
        let s = serde_json::to_string(&ForwardReason::Capability).unwrap();
        assert_eq!(s, "\"capability\"");
    }

    // ── ClusterRequestForwardedPayload ──────────────────────────

    #[test]
    fn forwarded_constructor_stores_inputs() {
        let p = ClusterRequestForwardedPayload::new(
            "req-7f3a",
            "0123abcd0123abcd",
            ForwardReason::Capability,
            1_700_000_000,
        );
        assert_eq!(p.request_id, "req-7f3a");
        assert_eq!(p.target_peer_pubkey, "0123abcd0123abcd");
        assert_eq!(p.reason, ForwardReason::Capability);
        assert_eq!(p.ts_unix, 1_700_000_000);
    }

    #[test]
    fn forwarded_to_bytes_emits_valid_json_with_required_fields() {
        let p = ClusterRequestForwardedPayload::new(
            "req-7f3a",
            "0123abcd",
            ForwardReason::Fallback,
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_slice(&p.to_bytes()).unwrap();
        assert_eq!(v["request_id"], "req-7f3a");
        assert_eq!(v["target_peer_pubkey"], "0123abcd");
        assert_eq!(v["reason"], "fallback");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn forwarded_serde_round_trips() {
        let original =
            ClusterRequestForwardedPayload::new("req-X", "peer-Y", ForwardReason::Affinity, 42);
        let bytes = original.to_bytes();
        let back: ClusterRequestForwardedPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, original);
    }
}
