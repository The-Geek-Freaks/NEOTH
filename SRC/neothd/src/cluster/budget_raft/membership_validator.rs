//! Durable membership proof for the fixed-voter budget authority.
//!
//! A wire tuple is never enough for a budget voter. This module derives the
//! frozen configuration and every later admission from one fresh, coherent
//! `MembershipStore::full_snapshot()` read on the blocking pool.

use super::service::{
    AuthenticatedBudgetPeer, AuthenticatedLocalInvocation, BudgetInboundError,
    BudgetMembershipValidator, BudgetServiceError,
};
use super::types::BudgetClusterConfig;
use crate::cluster::membership::{
    CarrierKind, LocalNodeIdentity, MembershipSnapshot, MembershipState, MembershipStore,
    StableNodeId, TransportIdentity,
};
use crate::config::BudgetRaftConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The runtime authority reader. It holds only a path: every check opens the
/// durable authority on `spawn_blocking`, so cached grants and a caller-made
/// `(stable id, transport key)` tuple cannot survive a revoke or epoch change.
#[derive(Clone, Debug)]
pub(crate) struct DurableBudgetMembershipValidator {
    authority_home: PathBuf,
    local_transport_identity: TransportIdentity,
}

impl DurableBudgetMembershipValidator {
    pub(crate) fn new(home: impl AsRef<Path>, identity: &LocalNodeIdentity) -> Self {
        Self {
            authority_home: home.as_ref().to_path_buf(),
            local_transport_identity: TransportIdentity::peeroxide(
                &identity.peeroxide_key_pair().public_key,
            ),
        }
    }

    /// Builds a frozen OpenRaft config only when the supplied policy agrees
    /// exactly with the current durable authority. The caller must invoke this
    /// before opening `budget-raft.db`; a mismatch therefore never repairs,
    /// migrates, or resets an existing authority database.
    pub(crate) async fn derive_frozen_config(
        &self,
        cluster_id: String,
        configured: &BudgetRaftConfig,
        local_identity: &LocalNodeIdentity,
    ) -> Result<BudgetClusterConfig> {
        anyhow::ensure!(configured.enabled, "budget raft is not enabled");
        let configured = configured.clone();
        let expected_local = local_identity.stable_node_id().clone();
        let expected_transport = self.local_transport_identity.clone();
        let authority_home = self.authority_home.clone();
        tokio::task::spawn_blocking(move || {
            let snapshot = MembershipStore::open(&authority_home)
                .context("open durable membership authority for budget raft")?
                .full_snapshot()
                .context("read coherent membership snapshot for budget raft")?;
            derive_from_snapshot(
                cluster_id,
                &configured,
                &expected_local,
                &expected_transport,
                &snapshot,
                crate::time::now_unix_i64(),
            )
        })
        .await
        .map_err(|error| anyhow::anyhow!("budget membership snapshot task failed: {error}"))?
    }

    async fn snapshot(&self) -> Result<MembershipSnapshot> {
        let authority_home = self.authority_home.clone();
        tokio::task::spawn_blocking(move || {
            MembershipStore::open(&authority_home)
                .context("open durable membership authority")?
                .full_snapshot()
                .context("read coherent durable membership snapshot")
        })
        .await
        .map_err(|error| anyhow::anyhow!("membership snapshot task failed: {error}"))?
    }
}

#[async_trait]
impl BudgetMembershipValidator for DurableBudgetMembershipValidator {
    async fn revalidate_local(
        &self,
        expected: &BudgetClusterConfig,
        expected_local: &StableNodeId,
    ) -> Result<AuthenticatedLocalInvocation, BudgetServiceError> {
        let snapshot = self.snapshot().await.map_err(unavailable)?;
        verify_snapshot(expected, &snapshot, crate::time::now_unix_i64()).map_err(unavailable)?;
        let expected_transport =
            expected
                .voters
                .get(expected_local)
                .ok_or(BudgetServiceError::Configuration(
                    "local stable identity is not a frozen budget voter",
                ))?;
        if expected_transport != &self.local_transport_identity
            || !snapshot_has_current_binding(
                &snapshot,
                expected_local,
                expected_transport,
                crate::time::now_unix_i64(),
            )
        {
            return Err(BudgetServiceError::Unavailable(
                "local stable identity or Peeroxide transport binding is no longer current".into(),
            ));
        }
        Ok(
            AuthenticatedLocalInvocation::from_revalidated_local_session(
                expected_local.clone(),
                expected_transport.clone(),
                expected.membership_epoch,
            ),
        )
    }

    async fn revalidate_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        expected: &BudgetClusterConfig,
    ) -> Result<(), BudgetInboundError> {
        let snapshot = self.snapshot().await.map_err(inbound_unavailable)?;
        verify_snapshot(expected, &snapshot, crate::time::now_unix_i64())
            .map_err(inbound_unavailable)?;
        let expected_transport = expected
            .voters
            .get(peer.stable_node_id())
            .ok_or(BudgetInboundError::AuthenticationMismatch)?;
        if peer.membership_epoch() != expected.membership_epoch
            || peer.transport_identity() != expected_transport
            || !snapshot_has_current_binding(
                &snapshot,
                peer.stable_node_id(),
                expected_transport,
                crate::time::now_unix_i64(),
            )
        {
            return Err(BudgetInboundError::AuthenticationMismatch);
        }
        Ok(())
    }
}

/// Strictly converts operator config to the canonical map, then requires the
/// same full active snapshot. This makes config case/spelling ambiguity and a
/// stale revoked binding fail closed before Raft receives a carrier.
fn derive_from_snapshot(
    cluster_id: String,
    configured: &BudgetRaftConfig,
    expected_local: &StableNodeId,
    expected_transport: &TransportIdentity,
    snapshot: &MembershipSnapshot,
    now_unix: i64,
) -> Result<BudgetClusterConfig> {
    anyhow::ensure!(
        configured.cap_usd_nanos > 0 && configured.utc_window > 0,
        "budget cap and UTC window must be positive"
    );
    anyhow::ensure!(
        configured.membership_epoch > 0,
        "budget membership epoch must be positive"
    );
    anyhow::ensure!(
        configured.voters.len() == 3,
        "budget authority requires exactly three configured voters"
    );
    let voters = configured
        .voters
        .iter()
        .map(|voter| {
            Ok((
                StableNodeId::parse(voter.stable_node_id.clone())?,
                TransportIdentity::parse(voter.peeroxide_key.clone())?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    anyhow::ensure!(
        voters.len() == 3,
        "budget authority has duplicate configured stable node ids"
    );
    anyhow::ensure!(
        voters
            .values()
            .map(|transport| transport.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 3,
        "budget authority has duplicate configured peeroxide keys"
    );
    let config = BudgetClusterConfig::new(
        cluster_id,
        configured.membership_epoch,
        voters,
        configured.cap_usd_nanos,
        configured.utc_window,
    )
    .map_err(|error| anyhow::anyhow!("invalid fixed budget configuration: {error:?}"))?;
    verify_snapshot(&config, snapshot, now_unix)?;
    anyhow::ensure!(
        config.voters.get(expected_local) == Some(expected_transport),
        "local stable identity and own Peeroxide transport key are not an exact configured budget voter"
    );
    Ok(config)
}

fn verify_snapshot(
    expected: &BudgetClusterConfig,
    snapshot: &MembershipSnapshot,
    now_unix: i64,
) -> Result<()> {
    snapshot
        .validate()
        .context("membership snapshot is malformed")?;
    anyhow::ensure!(
        snapshot.pending_outbox == 0,
        "membership authority has pending outbox work"
    );
    anyhow::ensure!(
        snapshot.authority_epoch.get() == expected.membership_epoch,
        "membership authority epoch differs from frozen budget epoch"
    );
    anyhow::ensure!(
        snapshot.revocation_floor <= snapshot.authority_epoch,
        "membership revocation floor is invalid"
    );
    for (stable, transport) in &expected.voters {
        anyhow::ensure!(
            snapshot_has_current_binding(snapshot, stable, transport, now_unix),
            "frozen budget voter {stable} is inactive, revoked, expired, or has a changed Peeroxide binding"
        );
    }
    Ok(())
}

fn snapshot_has_current_binding(
    snapshot: &MembershipSnapshot,
    stable: &StableNodeId,
    transport: &TransportIdentity,
    now_unix: i64,
) -> bool {
    snapshot
        .members
        .iter()
        .find(|member| &member.stable_node_id == stable)
        .is_some_and(|member| {
            member.state == MembershipState::Active
                && !member.tombstoned
                && member.membership_epoch.get() == snapshot.authority_epoch.get()
                && member.membership_epoch.get() >= snapshot.revocation_floor.get()
                && member.bindings.iter().any(|binding| {
                    binding.carrier == CarrierKind::Peeroxide
                        && &binding.transport_identity == transport
                        && binding.auth_epoch == member.auth_epoch
                        && binding.membership_epoch == member.membership_epoch
                        && binding
                            .expires_at_unix
                            .is_none_or(|expiry| expiry > now_unix)
                })
        })
}

fn unavailable(error: anyhow::Error) -> BudgetServiceError {
    BudgetServiceError::Unavailable(format!(
        "durable budget membership revalidation failed: {error:#}"
    ))
}

fn inbound_unavailable(error: anyhow::Error) -> BudgetInboundError {
    BudgetInboundError::Unavailable(format!(
        "durable budget membership revalidation failed: {error:#}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::membership::{
        AuthEpoch, CarrierBindingSnapshot, MEMBERSHIP_SNAPSHOT_VERSION, MemberSnapshot,
        MembershipEpoch,
    };
    use crate::config::BudgetRaftVoterConfig;

    fn stable(byte: char) -> StableNodeId {
        StableNodeId::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn transport(byte: char) -> TransportIdentity {
        TransportIdentity::parse(byte.to_string().repeat(64)).unwrap()
    }

    fn policy() -> BudgetRaftConfig {
        BudgetRaftConfig {
            enabled: true,
            cap_usd_nanos: 100,
            utc_window: 20_260_923,
            membership_epoch: 7,
            voters: [('1', 'a'), ('2', 'b'), ('3', 'c')]
                .into_iter()
                .map(|(id, key)| BudgetRaftVoterConfig {
                    stable_node_id: id.to_string().repeat(64),
                    peeroxide_key: key.to_string().repeat(64),
                })
                .collect(),
        }
    }

    fn snapshot(epoch: u64) -> MembershipSnapshot {
        MembershipSnapshot {
            version: MEMBERSHIP_SNAPSHOT_VERSION,
            authority_path: PathBuf::from("test-membership-authority"),
            authority_epoch: MembershipEpoch::new(epoch).unwrap(),
            revocation_floor: MembershipEpoch::new(epoch).unwrap(),
            pending_outbox: 0,
            members: [('1', 'a'), ('2', 'b'), ('3', 'c')]
                .into_iter()
                .map(|(id, key)| MemberSnapshot {
                    stable_node_id: stable(id),
                    label: format!("voter-{id}"),
                    state: MembershipState::Active,
                    auth_epoch: AuthEpoch::new(4).unwrap(),
                    membership_epoch: MembershipEpoch::new(epoch).unwrap(),
                    tombstoned: false,
                    bindings: vec![CarrierBindingSnapshot {
                        carrier: CarrierKind::Peeroxide,
                        transport_identity: transport(key),
                        endpoint: format!("127.0.0.1:{}", 9_000 + id as u16),
                        assurance: "signed_attestation".into(),
                        auth_epoch: AuthEpoch::new(4).unwrap(),
                        membership_epoch: MembershipEpoch::new(epoch).unwrap(),
                        expires_at_unix: None,
                    }],
                })
                .collect(),
        }
    }

    #[test]
    fn exact_current_snapshot_derives_the_three_fixed_peeroxide_voters() {
        let policy = policy();
        let local = stable('1');
        let config = derive_from_snapshot(
            "budget-mesh".into(),
            &policy,
            &local,
            &transport('a'),
            &snapshot(7),
            1,
        )
        .unwrap();

        assert_eq!(config.cluster_id, "budget-mesh");
        assert_eq!(config.membership_epoch, 7);
        assert_eq!(config.voters.len(), 3);
        assert_eq!(config.voters.get(&local), Some(&transport('a')));
    }

    #[test]
    fn revoked_frozen_voter_fails_closed() {
        let policy = policy();
        let local = stable('1');
        let local_transport = transport('a');

        let mut revoked = snapshot(7);
        revoked.members[1].state = MembershipState::Revoked;
        revoked.members[1].tombstoned = true;
        assert!(
            derive_from_snapshot(
                "budget-mesh".into(),
                &policy,
                &local,
                &local_transport,
                &revoked,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn changed_membership_epoch_fails_closed() {
        let policy = policy();
        let local = stable('1');
        let local_transport = transport('a');

        assert!(
            derive_from_snapshot(
                "budget-mesh".into(),
                &policy,
                &local,
                &local_transport,
                &snapshot(8),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn configured_peeroxide_binding_mismatch_fails_closed() {
        let policy = policy();
        let local = stable('1');
        let local_transport = transport('a');
        let mut changed_binding = policy.clone();
        changed_binding.voters[2].peeroxide_key = "d".repeat(64);
        assert!(
            derive_from_snapshot(
                "budget-mesh".into(),
                &changed_binding,
                &local,
                &local_transport,
                &snapshot(7),
                1,
            )
            .is_err()
        );
    }
}
