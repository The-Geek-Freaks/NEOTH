//! Quorum-only budget service facade.
//!
//! `ReservedGrant` is durable evidence of a reservation, never a provider
//! permit.  The sole executable capability is `NewDispatchPermit`, created in
//! this module only for the invocation that observes the first committed claim.

use super::network::{BudgetPeerRoute, BudgetRaftCarrier, BudgetRaftNetworkFactory};
use super::raft_types::BudgetTypeConfig;
use super::state_machine::BudgetLedger;
use super::store;
use super::types::{
    BeginDispatch, BudgetClusterConfig, BudgetCommand, BudgetRejection, BudgetReply, ClaimReceipt,
    DispatchAttemptId, DispatchFence, GrantFence, GrantReceipt, ReserveBudget, ReservedGrant,
    SettleBudget,
};
use crate::cluster::membership::{LocalNodeIdentity, StableNodeId, TransportIdentity};
use async_trait::async_trait;
use openraft::error::RaftError;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const SERVICE_DB_NAME: &str = "budget-raft.db";
const RPC_TIMEOUT: Duration = Duration::from_secs(4);
const ELECTION_MIN_MS: u64 = 900;
const ELECTION_MAX_MS: u64 = 1_500;
const HEARTBEAT_MS: u64 = 250;
const MAX_REPLICATION_ENTRIES: u64 = 32;

/// A value minted by the authenticated local provider-admission seam.  It is
/// not serializable or cloneable, and its fields remain private so a receipt,
/// replayed reply, or restart cannot recreate a provider-call capability.
pub struct NewDispatchPermit {
    grant_id: super::types::BudgetGrantId,
    dispatch_fence: DispatchFence,
    owner: StableNodeId,
    attempt_id: DispatchAttemptId,
    provider_intent_id: String,
    claim_receipt: ClaimReceipt,
}

impl std::fmt::Debug for NewDispatchPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDispatchPermit")
            .field("grant_id", &self.grant_id)
            .field("owner", &self.owner)
            .field("attempt_id", &self.attempt_id)
            .field("provider_intent_id", &"<bound>")
            .finish_non_exhaustive()
    }
}

impl NewDispatchPermit {
    pub fn grant_id(&self) -> &super::types::BudgetGrantId {
        &self.grant_id
    }
    pub fn owner(&self) -> &StableNodeId {
        &self.owner
    }
    pub fn attempt_id(&self) -> &DispatchAttemptId {
        &self.attempt_id
    }
    pub(crate) fn claim_receipt(&self) -> ClaimReceipt {
        self.claim_receipt.clone()
    }
}

/// Leaf input for one provider invocation. `invocation_id` and fingerprint are
/// immutable caller-owned idempotency material; this service creates the UUIDv7
/// grant id after validating the bounded monetary request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BudgetProviderRequest {
    pub invocation_id: String,
    pub provider_intent_id: String,
    pub provider: String,
    pub model: String,
    pub task_id: String,
    pub request_binding_sha256: String,
    pub bound_usd_nanos: u64,
}

/// The accounting half of one admitted provider call.  It cannot mint another
/// permit.  Once the permit is taken, cancellation must settle `None`, which
/// keeps the whole bound until reconciliation instead of releasing it.
pub(crate) struct BudgetProviderDispatch {
    service: Arc<BudgetRaftService>,
    claim: ClaimReceipt,
    permit: Option<NewDispatchPermit>,
}
pub(crate) type ProviderDispatchTicket = BudgetProviderDispatch;

impl BudgetProviderDispatch {
    pub(crate) fn take_provider_permit(&mut self) -> Result<NewDispatchPermit, BudgetServiceError> {
        self.permit.take().ok_or(BudgetServiceError::Unavailable(
            "provider permit was already consumed; reconcile or settle only".into(),
        ))
    }
    pub(crate) async fn settle_after_provider_call(
        self,
        actual_usd_nanos: Option<u64>,
    ) -> Result<GrantReceipt, BudgetServiceError> {
        if self.permit.is_some() {
            return Err(BudgetServiceError::Unavailable(
                "provider permit was not consumed; release before claim instead".into(),
            ));
        }
        self.service
            .settle_reconciliation(self.claim, actual_usd_nanos)
            .await
    }
}

/// Non-wire proof supplied by the provider-admission runtime after it has
/// revalidated the current local membership session.  It is intentionally
/// crate-private: remote carrier frames are Raft transport only and cannot call
/// `begin_dispatch` to receive a permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedLocalInvocation {
    stable_node_id: StableNodeId,
    transport_identity: TransportIdentity,
    membership_epoch: u64,
}

impl AuthenticatedLocalInvocation {
    pub(crate) fn from_revalidated_local_session(
        stable_node_id: StableNodeId,
        transport_identity: TransportIdentity,
        membership_epoch: u64,
    ) -> Self {
        Self {
            stable_node_id,
            transport_identity,
            membership_epoch,
        }
    }
}

/// Runtime-owned membership revalidation.  The service refuses to rely on a
/// caller-created identity tuple: each admission and inbound Raft RPC must be
/// checked again against the live accepted membership authority.
#[async_trait]
pub(crate) trait BudgetMembershipValidator: Send + Sync + 'static {
    async fn revalidate_local(
        &self,
        expected: &BudgetClusterConfig,
        expected_local: &StableNodeId,
    ) -> Result<AuthenticatedLocalInvocation, BudgetServiceError>;

    async fn revalidate_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        expected: &BudgetClusterConfig,
    ) -> Result<(), BudgetInboundError>;
}

/// Non-wire peer identity constructed only by the authenticated Peeroxide
/// session router.  The asserted sender inside a budget envelope is checked by
/// that router against this value before it reaches the service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedBudgetPeer {
    stable_node_id: StableNodeId,
    transport_identity: TransportIdentity,
    membership_epoch: u64,
}

impl AuthenticatedBudgetPeer {
    pub(crate) fn from_revalidated_peer_session(
        stable_node_id: StableNodeId,
        transport_identity: TransportIdentity,
        membership_epoch: u64,
    ) -> Self {
        Self {
            stable_node_id,
            transport_identity,
            membership_epoch,
        }
    }
    pub(crate) fn stable_node_id(&self) -> &StableNodeId {
        &self.stable_node_id
    }
    pub(crate) fn transport_identity(&self) -> &TransportIdentity {
        &self.transport_identity
    }
    pub(crate) fn membership_epoch(&self) -> u64 {
        self.membership_epoch
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BudgetInboundError {
    #[error("budget raft peer is not an authenticated frozen voter")]
    AuthenticationMismatch,
    #[error("budget raft inbound operation is unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetServiceError {
    #[error("budget raft configuration is invalid: {0}")]
    Configuration(&'static str),
    #[error("budget raft durable recovery failed: {0}")]
    Recovery(String),
    #[error("budget raft is unavailable: {0}")]
    Unavailable(String),
    #[error("budget operation was rejected: {0:?}")]
    Rejected(BudgetRejection),
    #[error("budget raft returned an unexpected reply")]
    UnexpectedReply,
    #[error("budget dispatch invocation is not the authenticated local voter")]
    OriginMismatch,
}

/// A recovered OpenRaft node plus the immutable configuration that authorizes
/// it.  It has no local counter or leader shortcut.
pub struct BudgetRaftService {
    raft: openraft::Raft<BudgetTypeConfig>,
    config: BudgetClusterConfig,
    local_node_id: u64,
    local_stable_node_id: StableNodeId,
    local_transport_identity: TransportIdentity,
    membership_validator: Arc<dyn BudgetMembershipValidator>,
    stopping: watch::Sender<bool>,
    carrier: Arc<dyn BudgetRaftCarrier>,
    routes: BTreeMap<u64, BudgetPeerRoute>,
}

impl BudgetRaftService {
    /// Opens or recovers the local durable voter.  Store opening occurs on the
    /// blocking pool; an absent/corrupt store is an error, never a reset.  This
    /// constructor deliberately does not initialize membership: bootstrap is a
    /// separate, exact-three-voter call after all authenticated carriers exist.
    pub(crate) async fn recover(
        home: impl AsRef<Path>,
        config: BudgetClusterConfig,
        identity: &LocalNodeIdentity,
        carrier: Arc<dyn BudgetRaftCarrier>,
        membership_validator: Arc<dyn BudgetMembershipValidator>,
    ) -> Result<Self, BudgetServiceError> {
        validate_config(&config)?;
        let routes = derive_routes(&config)?;
        let local_stable_node_id = identity.stable_node_id().clone();
        let local_node_id =
            config
                .raft_node_id(&local_stable_node_id)
                .ok_or(BudgetServiceError::Configuration(
                    "local stable identity is not a frozen voter",
                ))?;
        let local_transport_identity = config.voters.get(&local_stable_node_id).cloned().ok_or(
            BudgetServiceError::Configuration("local voter lacks a transport binding"),
        )?;

        let path = home.as_ref().join(SERVICE_DB_NAME);
        let initial = BudgetLedger::new(config.clone()).map_err(BudgetServiceError::Rejected)?;
        let store = tokio::task::spawn_blocking(move || store::open(&path, initial))
            .await
            .map_err(|error| BudgetServiceError::Recovery(format!("store task failed: {error}")))?
            .map_err(|error| BudgetServiceError::Recovery(error.to_string()))?;
        let network =
            BudgetRaftNetworkFactory::new(Arc::clone(&carrier), routes.clone(), RPC_TIMEOUT)
                .map_err(BudgetServiceError::Configuration)?;
        let raft_config = raft_runtime_config(&config)?;
        let raft = openraft::Raft::new(
            local_node_id,
            Arc::new(raft_config),
            network,
            store.clone(),
            store,
        )
        .await
        .map_err(|error| BudgetServiceError::Recovery(format!("start OpenRaft: {error}")))?;

        let (stopping, _stop_rx) = watch::channel(false);
        Ok(Self {
            raft,
            config,
            local_node_id,
            local_stable_node_id,
            local_transport_identity,
            membership_validator,
            stopping,
            carrier,
            routes,
        })
    }

    pub fn config(&self) -> &BudgetClusterConfig {
        &self.config
    }

    #[cfg(test)]
    pub(crate) async fn current_leader_node(&self) -> Option<u64> {
        self.raft.current_leader().await
    }

    /// Bootstrap only the frozen three-voter map.  Callers may invoke this on
    /// every fresh voter; OpenRaft safely rejects the losing race.  No dynamic
    /// member, learner, or caller-provided address can enter this path.
    pub async fn bootstrap_fixed_voters(&self) -> Result<(), BudgetServiceError> {
        if self.raft.is_initialized().await.map_err(raft_unavailable)? {
            return Ok(());
        }
        let members = self.config.raft_voters();
        match self.raft.initialize(members).await {
            Ok(()) => Ok(()),
            Err(RaftError::APIError(openraft::error::InitializeError::NotAllowed(_))) => {
                Ok(())
            }
            Err(error) => Err(BudgetServiceError::Unavailable(format!(
                "bootstrap fixed voters: {error}"
            ))),
        }
    }

    pub async fn reserve(
        &self,
        request: ReserveBudget,
    ) -> Result<ReservedGrant, BudgetServiceError> {
        match self.write(BudgetCommand::Reserve(request)).await? {
            BudgetReply::Reserved(grant) | BudgetReply::AlreadyReserved(grant) => Ok(grant),
            BudgetReply::Rejected(reason) => Err(BudgetServiceError::Rejected(reason)),
            _ => Err(BudgetServiceError::UnexpectedReply),
        }
    }

    /// Claims a previously durable provider intent.  This leaves idempotent
    /// intent persistence with the provider leaf and makes the first committed
    /// BeginDispatch reply the only source of an executable permit.
    pub(crate) async fn claim_provider_dispatch(
        self: &Arc<Self>,
        grant: &ReservedGrant,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderDispatchTicket, BudgetServiceError> {
        let origin = self
            .membership_validator
            .revalidate_local(&self.config, &self.local_stable_node_id)
            .await?;
        let request = BeginDispatch {
            grant_id: grant.grant_id.clone(),
            reserve_fence: grant.reserve_fence.clone(),
            owner: self.local_stable_node_id.clone(),
            attempt_id,
            provider_intent_id: grant.provider_intent_id.clone(),
        };
        let permit = self.begin_dispatch(&origin, request).await?;
        let claim = permit.claim_receipt();
        Ok(BudgetProviderDispatch {
            service: Arc::clone(self),
            claim,
            permit: Some(permit),
        })
    }

    /// Convenience for leaves which have already durably created their intent
    /// but need this authority to mint a UUIDv7 grant.  The invocation id is
    /// incorporated into the fingerprint so a provider cannot accidentally
    /// share a reservation across two distinct leaf invocations.
    pub(crate) async fn reserve_and_begin_provider_dispatch(
        self: &Arc<Self>,
        request: BudgetProviderRequest,
    ) -> Result<ProviderDispatchTicket, BudgetServiceError> {
        if request.invocation_id.is_empty()
            || request.provider_intent_id.is_empty()
            || request.provider.is_empty()
            || request.model.is_empty()
            || request.task_id.is_empty()
            || !is_sha256_hex(&request.request_binding_sha256)
            || request.bound_usd_nanos == 0
        {
            return Err(BudgetServiceError::Configuration(
                "provider budget request has an empty identity or zero bound",
            ));
        }
        let grant = self
            .reserve(ReserveBudget {
                grant_id: super::types::BudgetGrantId(uuid::Uuid::now_v7().to_string()),
                provider_intent_id: request.provider_intent_id.clone(),
                request_fingerprint: provider_request_fingerprint(
                    &self.config,
                    &self.local_stable_node_id,
                    &request,
                ),
                scope_hash: self.config.scope_hash.clone(),
                reserved_usd_nanos: request.bound_usd_nanos,
                utc_window: self.config.utc_window,
            })
            .await?;
        match self
            .claim_provider_dispatch(&grant, DispatchAttemptId(uuid::Uuid::now_v7().to_string()))
            .await
        {
            Ok(ticket) => Ok(ticket),
            Err(error) => {
                // This replicated transition is safe only while the grant is
                // still Reserved.  If a claim actually committed while its
                // reply was lost, the state machine rejects release and the
                // reservation remains held for reconciliation.  Keep the
                // original claim failure visible to the caller either way.
                let _ = self
                    .release_before_claim(grant.grant_id.clone(), grant.reserve_fence.clone())
                    .await;
                Err(error)
            }
        }
    }

    /// The only minting point for `NewDispatchPermit`.  A response replay,
    /// duplicate BeginDispatch, or a recovered claim maps to reconciliation and
    /// cannot return another executable capability.
    pub(crate) async fn begin_dispatch(
        &self,
        origin: &AuthenticatedLocalInvocation,
        request: BeginDispatch,
    ) -> Result<NewDispatchPermit, BudgetServiceError> {
        let fresh = self
            .membership_validator
            .revalidate_local(&self.config, &self.local_stable_node_id)
            .await?;
        if &fresh != origin {
            return Err(BudgetServiceError::OriginMismatch);
        }
        self.verify_local_origin(&fresh, &request.owner)?;
        match self.write(BudgetCommand::BeginDispatch(request)).await? {
            BudgetReply::NewClaimed(receipt) => Ok(NewDispatchPermit {
                grant_id: receipt.grant_id.clone(),
                dispatch_fence: receipt.dispatch_fence.clone(),
                owner: receipt.owner.clone(),
                attempt_id: receipt.attempt_id.clone(),
                provider_intent_id: receipt.provider_intent_id.clone(),
                claim_receipt: receipt,
            }),
            BudgetReply::AlreadyClaimed(_) | BudgetReply::ReconcileOnly(_) => {
                Err(BudgetServiceError::Unavailable(
                    "claim is already committed; reconcile before any provider retry".into(),
                ))
            }
            BudgetReply::Rejected(reason) => Err(BudgetServiceError::Rejected(reason)),
            _ => Err(BudgetServiceError::UnexpectedReply),
        }
    }

    /// Consumes the capability, so completion is forever bound to the exact
    /// first claim.  `None` preserves the full reservation bound in the state
    /// machine as required for an unknown provider outcome.
    pub async fn settle(
        &self,
        permit: NewDispatchPermit,
        actual_usd_nanos: Option<u64>,
    ) -> Result<GrantReceipt, BudgetServiceError> {
        let request = SettleBudget {
            grant_id: permit.grant_id,
            dispatch_fence: permit.dispatch_fence,
            owner: permit.owner,
            attempt_id: permit.attempt_id,
            actual_usd_nanos,
        };
        match self.write(BudgetCommand::Settle(request)).await? {
            BudgetReply::Settled(receipt) => Ok(receipt),
            BudgetReply::Rejected(reason) => Err(BudgetServiceError::Rejected(reason)),
            _ => Err(BudgetServiceError::UnexpectedReply),
        }
    }

    /// Recovery-only terminal path.  It accepts a committed claim receipt and
    /// can therefore finish accounting after a lost settlement ACK, but it
    /// never creates a provider permit or dispatches work.
    pub async fn settle_reconciliation(
        &self,
        receipt: ClaimReceipt,
        actual_usd_nanos: Option<u64>,
    ) -> Result<GrantReceipt, BudgetServiceError> {
        let request = SettleBudget {
            grant_id: receipt.grant_id,
            dispatch_fence: receipt.dispatch_fence,
            owner: receipt.owner,
            attempt_id: receipt.attempt_id,
            actual_usd_nanos,
        };
        match self.write(BudgetCommand::Settle(request)).await? {
            BudgetReply::Settled(receipt) => Ok(receipt),
            BudgetReply::Rejected(reason) => Err(BudgetServiceError::Rejected(reason)),
            _ => Err(BudgetServiceError::UnexpectedReply),
        }
    }

    pub async fn release_before_claim(
        &self,
        grant_id: super::types::BudgetGrantId,
        reserve_fence: GrantFence,
    ) -> Result<GrantReceipt, BudgetServiceError> {
        match self
            .write(BudgetCommand::ReleaseBeforeClaim {
                grant_id,
                reserve_fence,
            })
            .await?
        {
            BudgetReply::Released(receipt) => Ok(receipt),
            BudgetReply::Rejected(reason) => Err(BudgetServiceError::Rejected(reason)),
            _ => Err(BudgetServiceError::UnexpectedReply),
        }
    }

    pub async fn shutdown(&self) -> Result<(), BudgetServiceError> {
        // `send()` may fail after the constructor's initial receiver is
        // dropped; `send_replace()` persists the stop bit for all later
        // writer/inbound checks regardless of active subscribers.
        self.stopping.send_replace(true);
        self.raft
            .clone()
            .shutdown()
            .await
            .map_err(|error| BudgetServiceError::Unavailable(format!("shutdown OpenRaft: {error}")))
    }

    /// Typed carrier ingress.  The caller must obtain `peer` from the current
    /// authenticated Noise session; an envelope field can only be compared to
    /// it and can never select a voter or route.
    pub(crate) async fn append_entries_from_authenticated_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        request: AppendEntriesRequest<BudgetTypeConfig>,
    ) -> Result<AppendEntriesResponse<u64>, BudgetInboundError> {
        self.verify_authenticated_peer(peer).await?;
        self.raft
            .append_entries(request)
            .await
            .map_err(inbound_unavailable)
    }

    pub(crate) async fn vote_from_authenticated_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        request: VoteRequest<u64>,
    ) -> Result<VoteResponse<u64>, BudgetInboundError> {
        self.verify_authenticated_peer(peer).await?;
        self.raft.vote(request).await.map_err(inbound_unavailable)
    }

    pub(crate) async fn install_snapshot_from_authenticated_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        request: InstallSnapshotRequest<BudgetTypeConfig>,
    ) -> Result<InstallSnapshotResponse<u64>, BudgetInboundError> {
        self.verify_authenticated_peer(peer).await?;
        self.raft
            .install_snapshot(request)
            .await
            .map_err(inbound_unavailable)
    }

    /// Authenticated follower-to-leader client-admission ingress.  The carrier
    /// has already fixed the route to this leader; this method never forwards.
    /// A reply is only domain data, so it cannot carry an executable permit.
    pub(crate) async fn command_from_authenticated_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
        command: BudgetCommand,
    ) -> Result<BudgetReply, BudgetInboundError> {
        self.verify_authenticated_peer(peer).await?;
        match &command {
            BudgetCommand::BeginDispatch(request) if request.owner != peer.stable_node_id => {
                return Err(BudgetInboundError::AuthenticationMismatch);
            }
            BudgetCommand::Settle(request) if request.owner != peer.stable_node_id => {
                return Err(BudgetInboundError::AuthenticationMismatch);
            }
            _ => {}
        }
        if self.raft.current_leader().await != Some(self.local_node_id) {
            return Err(BudgetInboundError::Unavailable(
                "budget command reached a nonleader; no forwarding is permitted".into(),
            ));
        }
        tokio::time::timeout(RPC_TIMEOUT, self.raft.client_write(command))
            .await
            .map_err(|_| BudgetInboundError::Unavailable("leader budget command timed out".into()))?
            .map(|response| response.data)
            .map_err(inbound_unavailable)
    }

    async fn write(&self, command: BudgetCommand) -> Result<BudgetReply, BudgetServiceError> {
        if *self.stopping.borrow() {
            return Err(BudgetServiceError::Unavailable(
                "budget service is stopping".into(),
            ));
        }
        let origin = self
            .membership_validator
            .revalidate_local(&self.config, &self.local_stable_node_id)
            .await?;
        self.verify_local_origin(&origin, &self.local_stable_node_id)?;
        let leader = self.raft.current_leader().await.ok_or_else(|| {
            BudgetServiceError::Unavailable("budget Raft has no known leader".into())
        })?;
        let mut stop = self.stopping.subscribe();
        let local = leader == self.local_node_id;
        let route = if local {
            None
        } else {
            Some(self.routes.get(&leader).cloned().ok_or_else(|| {
                BudgetServiceError::Unavailable("known leader is not a frozen budget voter".into())
            })?)
        };
        tokio::select! {
            _ = stop.changed() => Err(BudgetServiceError::Unavailable("budget service stopped before a quorum reply".into())),
            result = tokio::time::timeout(RPC_TIMEOUT, async {
                if local {
                    self.raft.client_write(command).await.map(|response| response.data).map_err(raft_unavailable)
                } else {
                    self.carrier.submit_budget_command(route.as_ref().expect("remote leader route exists"), command, RPC_TIMEOUT).await.map_err(raft_unavailable)
                }
            }) => match result {
                Ok(result) => result,
                Err(_) => Err(BudgetServiceError::Unavailable("quorum write timed out; reconcile immutable grant state before retrying".into())),
            },
        }
    }

    fn verify_local_origin(
        &self,
        origin: &AuthenticatedLocalInvocation,
        requested_owner: &StableNodeId,
    ) -> Result<(), BudgetServiceError> {
        if origin.stable_node_id != self.local_stable_node_id
            || origin.transport_identity != self.local_transport_identity
            || origin.membership_epoch != self.config.membership_epoch
            || requested_owner != &self.local_stable_node_id
            || self.local_node_id == 0
        {
            return Err(BudgetServiceError::OriginMismatch);
        }
        Ok(())
    }

    async fn verify_authenticated_peer(
        &self,
        peer: &AuthenticatedBudgetPeer,
    ) -> Result<(), BudgetInboundError> {
        if *self.stopping.borrow() {
            return Err(BudgetInboundError::Unavailable(
                "budget service is stopping".into(),
            ));
        }
        if peer.membership_epoch != self.config.membership_epoch
            || self.config.voters.get(&peer.stable_node_id) != Some(&peer.transport_identity)
        {
            return Err(BudgetInboundError::AuthenticationMismatch);
        }
        self.membership_validator
            .revalidate_peer(peer, &self.config)
            .await
    }
}

fn inbound_unavailable(error: impl std::fmt::Display) -> BudgetInboundError {
    BudgetInboundError::Unavailable(error.to_string())
}

fn raft_unavailable(error: impl std::fmt::Display) -> BudgetServiceError {
    BudgetServiceError::Unavailable(error.to_string())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value == value.to_ascii_lowercase()
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn provider_request_fingerprint(
    config: &BudgetClusterConfig,
    owner: &StableNodeId,
    request: &BudgetProviderRequest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"neoth.budget.provider-request.v1\0");
    for part in [
        request.invocation_id.as_bytes(),
        request.provider_intent_id.as_bytes(),
        request.provider.as_bytes(),
        request.model.as_bytes(),
        request.task_id.as_bytes(),
        request.request_binding_sha256.as_bytes(),
        owner.as_str().as_bytes(),
        &config.utc_window.to_le_bytes(),
        config.scope_hash.0.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

fn raft_runtime_config(
    config: &BudgetClusterConfig,
) -> Result<openraft::Config, BudgetServiceError> {
    let mut runtime = openraft::Config::default();
    runtime.cluster_name = format!("neoth-budget:{}:{}", config.cluster_id, config.scope_hash.0);
    runtime.election_timeout_min = ELECTION_MIN_MS;
    runtime.election_timeout_max = ELECTION_MAX_MS;
    runtime.heartbeat_interval = HEARTBEAT_MS;
    runtime.max_payload_entries = MAX_REPLICATION_ENTRIES;
    runtime.replication_lag_threshold = 256;
    runtime.validate().map_err(|_| {
        BudgetServiceError::Configuration(
            "OpenRaft runtime configuration rejected the frozen timing bounds",
        )
    })
}

fn validate_config(config: &BudgetClusterConfig) -> Result<(), BudgetServiceError> {
    BudgetLedger::new(config.clone()).map_err(BudgetServiceError::Rejected)?;
    if config.voters.len() != 3 || config.membership_epoch == 0 || config.cap_usd_nanos == 0 {
        return Err(BudgetServiceError::Configuration(
            "budget config must contain exactly three voters, a positive epoch, and a positive cap",
        ));
    }
    let mut transports = BTreeSet::new();
    if config
        .voters
        .values()
        .any(|transport| !transports.insert(transport.as_str().to_owned()))
    {
        return Err(BudgetServiceError::Configuration(
            "budget config has duplicate transport identities",
        ));
    }
    Ok(())
}

fn derive_routes(
    config: &BudgetClusterConfig,
) -> Result<BTreeMap<u64, BudgetPeerRoute>, BudgetServiceError> {
    let mut routes = BTreeMap::new();
    for (stable_node_id, transport_identity) in &config.voters {
        let node_id =
            config
                .raft_node_id(stable_node_id)
                .ok_or(BudgetServiceError::Configuration(
                    "frozen voter lacks a canonical Raft node id",
                ))?;
        if routes.contains_key(&node_id) {
            return Err(BudgetServiceError::Configuration(
                "canonical frozen voter mapping collided",
            ));
        }
        routes.insert(
            node_id,
            BudgetPeerRoute {
                node_id,
                stable_node_id: stable_node_id.clone(),
                transport_identity: transport_identity.clone(),
            },
        );
    }
    if routes.len() != 3 {
        return Err(BudgetServiceError::Configuration(
            "frozen voter routing is incomplete",
        ));
    }
    Ok(routes)
}
