//! Typed OpenRaft network boundary for the budget authority.
//!
//! This module deliberately has no dialer, loopback route, or generic frame
//! serializer.  A later Peeroxide session adapter implements `BudgetRaftCarrier`
//! only after it has checked the live Noise identity, membership grant, frozen
//! epoch, scope hash, bounded body, and cancellation ownership described in W420.

use super::raft_types::BudgetTypeConfig;
use super::types::{BudgetCommand, BudgetReply};
use crate::cluster::membership::{StableNodeId, TransportIdentity};
use async_trait::async_trait;
use openraft::error::{RPCError, RaftError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub type BudgetRpcError = RPCError<u64, openraft::BasicNode, RaftError<u64>>;
pub type BudgetSnapshotRpcError =
    RPCError<u64, openraft::BasicNode, RaftError<u64, openraft::error::InstallSnapshotError>>;

/// Frozen route selected from the accepted three-voter membership snapshot.
/// `node_id` is deterministic only inside this frozen configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetPeerRoute {
    pub node_id: u64,
    pub stable_node_id: StableNodeId,
    pub transport_identity: TransportIdentity,
}

/// The authenticated carrier seam.  Implementors receive a route that was
/// derived from the frozen config, never a caller-selected transport address.
///
/// Each method must reject an absent/revoked session, sender/config mismatch,
/// bounds violation, and timeout as `RPCError`; it may not self-route or retry
/// through a different member.  Inbound carrier code calls `Raft` directly only
/// after applying the corresponding authenticated session checks.
#[async_trait]
pub trait BudgetRaftCarrier: Send + Sync + 'static {
    /// Submit an origin-bound client command to the already selected frozen
    /// leader. The carrier must use one authenticated request/reply session;
    /// it must not follow leaders, self-route, or retry an ambiguous command.
    async fn submit_budget_command(
        &self,
        route: &BudgetPeerRoute,
        command: BudgetCommand,
        deadline: Duration,
    ) -> Result<BudgetReply, BudgetRpcError>;

    async fn append_entries(
        &self,
        route: &BudgetPeerRoute,
        request: AppendEntriesRequest<BudgetTypeConfig>,
        option: RPCOption,
        deadline: Duration,
    ) -> Result<AppendEntriesResponse<u64>, BudgetRpcError>;

    async fn install_snapshot(
        &self,
        route: &BudgetPeerRoute,
        request: InstallSnapshotRequest<BudgetTypeConfig>,
        option: RPCOption,
        deadline: Duration,
    ) -> Result<InstallSnapshotResponse<u64>, BudgetSnapshotRpcError>;

    async fn vote(
        &self,
        route: &BudgetPeerRoute,
        request: VoteRequest<u64>,
        option: RPCOption,
        deadline: Duration,
    ) -> Result<VoteResponse<u64>, BudgetRpcError>;
}

/// Network factory passed into OpenRaft.  Construction accepts only the exact
/// frozen mapping.  Missing routes stay unavailable: there is no local fallback.
#[derive(Clone)]
pub struct BudgetRaftNetworkFactory {
    carrier: Arc<dyn BudgetRaftCarrier>,
    routes: Arc<BTreeMap<u64, BudgetPeerRoute>>,
    request_timeout: Duration,
}

impl BudgetRaftNetworkFactory {
    pub fn new(
        carrier: Arc<dyn BudgetRaftCarrier>,
        routes: BTreeMap<u64, BudgetPeerRoute>,
        request_timeout: Duration,
    ) -> Result<Self, &'static str> {
        if routes.len() != 3 || request_timeout.is_zero() {
            return Err("budget raft network requires three routes and a non-zero timeout");
        }
        if routes.iter().any(|(id, route)| *id != route.node_id) {
            return Err("budget raft route key does not match route node id");
        }
        let mut identities = routes
            .values()
            .map(|route| route.stable_node_id.clone())
            .collect::<Vec<_>>();
        identities.sort();
        identities.dedup();
        if identities.len() != 3 {
            return Err("budget raft routes do not bind three distinct stable nodes");
        }
        Ok(Self {
            carrier,
            routes: Arc::new(routes),
            request_timeout,
        })
    }
}

pub struct BudgetRaftNetwork {
    carrier: Arc<dyn BudgetRaftCarrier>,
    route: Option<BudgetPeerRoute>,
    request_timeout: Duration,
}

#[openraft::add_async_trait]
impl RaftNetworkFactory<BudgetTypeConfig> for BudgetRaftNetworkFactory {
    type Network = BudgetRaftNetwork;

    async fn new_client(&mut self, target: u64, _node: &openraft::BasicNode) -> Self::Network {
        BudgetRaftNetwork {
            carrier: Arc::clone(&self.carrier),
            route: self.routes.get(&target).cloned(),
            request_timeout: self.request_timeout,
        }
    }
}

#[openraft::add_async_trait]
impl RaftNetwork<BudgetTypeConfig> for BudgetRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<BudgetTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, BudgetRpcError> {
        let route = self
            .route
            .as_ref()
            .ok_or_else(|| unreachable_error("unknown frozen budget voter"))?;
        self.carrier
            .append_entries(route, rpc, option, self.request_timeout)
            .await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<BudgetTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<u64>, BudgetSnapshotRpcError> {
        let route = self
            .route
            .as_ref()
            .ok_or_else(|| snapshot_unreachable_error("unknown frozen budget voter"))?;
        self.carrier
            .install_snapshot(route, rpc, option, self.request_timeout)
            .await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, BudgetRpcError> {
        let route = self
            .route
            .as_ref()
            .ok_or_else(|| unreachable_error("unknown frozen budget voter"))?;
        self.carrier
            .vote(route, rpc, option, self.request_timeout)
            .await
    }
}

fn unreachable_error(message: &'static str) -> BudgetRpcError {
    openraft::error::Unreachable::new(&std::io::Error::other(message)).into()
}

fn snapshot_unreachable_error(message: &'static str) -> BudgetSnapshotRpcError {
    openraft::error::Unreachable::new(&std::io::Error::other(message)).into()
}
