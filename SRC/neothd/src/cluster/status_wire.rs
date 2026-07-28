//! Strict shared wire contract for `neoth cluster status`.
//!
//! Membership authority state is carried only through the canonical
//! [`MembershipSnapshotEnvelope`]. Runtime posture is independently versioned
//! so it cannot become a second membership snapshot contract.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::membership::{MEMBERSHIP_SNAPSHOT_OPERATION, MembershipSnapshotEnvelope};

pub const CLUSTER_STATUS_WIRE_VERSION: u16 = 1;
pub const CLUSTER_STATUS_OPERATION: &str = "cluster.status";
pub const CLUSTER_RUNTIME_STATUS_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterStatusEnvelope {
    pub wire_version: u16,
    pub operation: String,
    pub membership: MembershipSnapshotEnvelope,
    pub runtime: ClusterRuntimeStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterRuntimeStatus {
    pub version: u16,
    pub mode: String,
    pub policy: String,
    pub conflict_count: usize,
    pub operator_id: String,
    pub node_id: String,
    pub cluster_name: Option<String>,
    pub cluster_passphrase_set: bool,
    pub cluster_identity_configured: bool,
    pub cluster_enabled: bool,
    pub restart_required: bool,
    pub transport_active: bool,
    pub transport: String,
    pub listen_port: u16,
    pub mdns_enabled: bool,
    pub trusted_ssids: Vec<String>,
    pub gossip: ClusterGossipStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterGossipStatus {
    pub replicate_raw_ingress: bool,
    pub replay_budget_days: u32,
}

impl ClusterStatusEnvelope {
    pub fn new(
        membership: MembershipSnapshotEnvelope,
        runtime: ClusterRuntimeStatus,
    ) -> Result<Self> {
        let envelope = Self {
            wire_version: CLUSTER_STATUS_WIRE_VERSION,
            operation: CLUSTER_STATUS_OPERATION.to_string(),
            membership,
            runtime,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let envelope =
            serde_json::from_str::<Self>(json).context("parse cluster status envelope JSON")?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.wire_version == CLUSTER_STATUS_WIRE_VERSION,
            "unsupported cluster status wire version"
        );
        anyhow::ensure!(
            self.operation == CLUSTER_STATUS_OPERATION,
            "unsupported cluster status operation"
        );
        anyhow::ensure!(
            self.membership.operation == MEMBERSHIP_SNAPSHOT_OPERATION,
            "cluster status embedded a non-canonical membership operation"
        );
        self.membership.validate()?;
        self.runtime.validate()
    }
}

impl ClusterRuntimeStatus {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == CLUSTER_RUNTIME_STATUS_VERSION,
            "unsupported cluster runtime status version"
        );
        anyhow::ensure!(
            matches!(self.mode.as_str(), "cluster" | "single-node"),
            "cluster runtime status mode is invalid"
        );
        anyhow::ensure!(
            matches!(
                self.policy.as_str(),
                "local-only"
                    | "discovery-off"
                    | "announce-any-network"
                    | "announce-trusted-wifi-only"
            ),
            "cluster runtime status policy is invalid"
        );
        anyhow::ensure!(
            !self.operator_id.trim().is_empty()
                && !self.node_id.trim().is_empty()
                && !self.transport.trim().is_empty(),
            "cluster runtime status identity is incomplete"
        );
        anyhow::ensure!(
            self.listen_port > 0,
            "cluster runtime status listen port is invalid"
        );
        anyhow::ensure!(
            !(self.transport_active && (!self.cluster_enabled || self.restart_required)),
            "cluster runtime status transport activation is inconsistent"
        );
        anyhow::ensure!(
            self.trusted_ssids
                .iter()
                .all(|ssid| !ssid.trim().is_empty() && ssid.trim() == ssid),
            "cluster runtime status contains invalid trusted SSID"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cluster::membership::{
        MEMBERSHIP_SNAPSHOT_VERSION, MembershipEpoch, MembershipSnapshot,
    };

    fn envelope() -> ClusterStatusEnvelope {
        let membership = MembershipSnapshot {
            version: MEMBERSHIP_SNAPSHOT_VERSION,
            authority_path: PathBuf::from("cluster-membership.db"),
            authority_epoch: MembershipEpoch::INITIAL,
            revocation_floor: MembershipEpoch::INITIAL,
            pending_outbox: 0,
            members: Vec::new(),
        }
        .into_envelope()
        .unwrap();
        let runtime = ClusterRuntimeStatus {
            version: CLUSTER_RUNTIME_STATUS_VERSION,
            mode: "single-node".into(),
            policy: "local-only".into(),
            conflict_count: 0,
            operator_id: "operator".into(),
            node_id: "node".into(),
            cluster_name: None,
            cluster_passphrase_set: false,
            cluster_identity_configured: false,
            cluster_enabled: false,
            restart_required: false,
            transport_active: false,
            transport: "peeroxide".into(),
            listen_port: 7700,
            mdns_enabled: false,
            trusted_ssids: Vec::new(),
            gossip: ClusterGossipStatus {
                replicate_raw_ingress: false,
                replay_budget_days: 14,
            },
        };
        ClusterStatusEnvelope::new(membership, runtime).unwrap()
    }

    #[test]
    fn status_envelope_is_strict_and_membership_digest_bound() {
        let envelope = envelope();
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(ClusterStatusEnvelope::from_json(&json).unwrap(), envelope);

        let mut unknown: serde_json::Value = serde_json::from_str(&json).unwrap();
        unknown["runtime"]["unexpected"] = serde_json::json!(true);
        assert!(ClusterStatusEnvelope::from_json(&unknown.to_string()).is_err());

        let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
        tampered["membership"]["snapshot"]["pending_outbox"] = serde_json::json!(1);
        assert!(ClusterStatusEnvelope::from_json(&tampered.to_string()).is_err());
    }

    #[test]
    fn status_envelope_rejects_inconsistent_runtime_activation() {
        let mut envelope = envelope();
        envelope.runtime.transport_active = true;
        assert!(envelope.validate().is_err());
    }
}
