//! Three-voter OpenRaft integration fixture for the budget authority.
//!
//! The carrier is only a bounded authenticated-carrier double. It never
//! implements consensus: every request enters the real `BudgetRaftService`
//! inbound RPC methods and is processed by three independent OpenRaft/SQLite
//! replicas.

use super::network::{BudgetPeerRoute, BudgetRaftCarrier, BudgetRpcError, BudgetSnapshotRpcError};
use super::raft_types::BudgetTypeConfig;
use super::service::{
    AuthenticatedBudgetPeer, AuthenticatedLocalInvocation, BudgetInboundError,
    BudgetMembershipValidator, BudgetRaftService, BudgetServiceError,
};
use super::types::{
    BeginDispatch, BudgetClusterConfig, BudgetGrantId, BudgetRejection, DispatchAttemptId,
    ReserveBudget,
};
use crate::cluster::membership::{LocalNodeIdentity, StableNodeId, TransportIdentity};
use async_trait::async_trait;
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Barrier;

const FIXTURE_EPOCH: u64 = 41;
const FIXTURE_WINDOW: i64 = 20_260_923;
const LEADER_WAIT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct FixtureMembershipValidator {
    config: BudgetClusterConfig,
}

#[async_trait]
impl BudgetMembershipValidator for FixtureMembershipValidator {
    async fn revalidate_local(
        &self,
        expected: &BudgetClusterConfig,
        expected_local: &StableNodeId,
    ) -> Result<AuthenticatedLocalInvocation, BudgetServiceError> {
        if expected != &self.config {
            return Err(BudgetServiceError::Configuration(
                "fixture received a different frozen budget config",
            ));
        }
        let transport = self
            .config
            .voters
            .get(expected_local)
            .cloned()
            .ok_or(BudgetServiceError::OriginMismatch)?;
        Ok(
            AuthenticatedLocalInvocation::from_revalidated_local_session(
                expected_local.clone(),
                transport,
                self.config.membership_epoch,
            ),
        )
    }

    async fn revalidate_peer(
        &self,
        _peer: &AuthenticatedBudgetPeer,
        expected: &BudgetClusterConfig,
    ) -> Result<(), BudgetInboundError> {
        if expected == &self.config {
            Ok(())
        } else {
            Err(BudgetInboundError::AuthenticationMismatch)
        }
    }
}

/// The registry intentionally contains weak service references so a restarted
/// replica cannot keep accepting RPCs through a stale in-process object.
struct FixtureCarrierRegistry {
    config: BudgetClusterConfig,
    services: Mutex<BTreeMap<u64, Weak<BudgetRaftService>>>,
    blocked_links: Mutex<BTreeSet<(u64, u64)>>,
    dropped_command_acks: Mutex<BTreeSet<(u64, u64)>>,
}

impl FixtureCarrierRegistry {
    fn new(config: BudgetClusterConfig) -> Self {
        Self {
            config,
            services: Mutex::new(BTreeMap::new()),
            blocked_links: Mutex::new(BTreeSet::new()),
            dropped_command_acks: Mutex::new(BTreeSet::new()),
        }
    }

    fn register(&self, node_id: u64, service: &Arc<BudgetRaftService>) {
        self.services
            .lock()
            .unwrap()
            .insert(node_id, Arc::downgrade(service));
    }

    fn remove(&self, node_id: u64) {
        self.services.lock().unwrap().remove(&node_id);
    }

    fn block_from(&self, origin: u64, targets: impl IntoIterator<Item = u64>) {
        let mut blocked = self.blocked_links.lock().unwrap();
        blocked.clear();
        blocked.extend(targets.into_iter().map(|target| (origin, target)));
    }

    fn isolate_both_directions(&self, isolated: u64, voters: impl IntoIterator<Item = u64>) {
        let mut blocked = self.blocked_links.lock().unwrap();
        blocked.clear();
        for peer in voters {
            if peer != isolated {
                blocked.insert((isolated, peer));
                blocked.insert((peer, isolated));
            }
        }
    }

    fn heal(&self) {
        self.blocked_links.lock().unwrap().clear();
    }

    fn drop_next_command_reply(&self, origin: u64, target: u64) {
        self.dropped_command_acks
            .lock()
            .unwrap()
            .insert((origin, target));
    }

    fn take_dropped_command_reply(&self, origin: u64, target: u64) -> bool {
        self.dropped_command_acks
            .lock()
            .unwrap()
            .remove(&(origin, target))
    }

    fn target(
        &self,
        origin: u64,
        route: &BudgetPeerRoute,
    ) -> Result<Arc<BudgetRaftService>, BudgetRpcError> {
        if self
            .blocked_links
            .lock()
            .unwrap()
            .contains(&(origin, route.node_id))
        {
            return Err(unreachable_rpc("fixture partition drops this target"));
        }
        self.services
            .lock()
            .unwrap()
            .get(&route.node_id)
            .and_then(Weak::upgrade)
            .ok_or_else(|| unreachable_rpc("fixture target is absent or restarted"))
    }

    fn authenticated_sender(&self, origin: u64) -> Result<AuthenticatedBudgetPeer, BudgetRpcError> {
        let (stable_node_id, transport_identity) = self
            .config
            .voters
            .iter()
            .find(|(stable_node_id, _)| self.config.raft_node_id(stable_node_id) == Some(origin))
            .ok_or_else(|| {
                unreachable_rpc("fixture origin is not an exact frozen voter binding")
            })?;
        Ok(AuthenticatedBudgetPeer::from_revalidated_peer_session(
            stable_node_id.clone(),
            transport_identity.clone(),
            self.config.membership_epoch,
        ))
    }
}

/// Each service gets a carrier permanently bound to its own source voter.
/// The registry is shared only for weak service discovery and link partitions;
/// destination routes never authenticate the origin of an inbound request.
struct FixtureCarrier {
    origin: u64,
    registry: Arc<FixtureCarrierRegistry>,
}

impl FixtureCarrier {
    fn new(origin: u64, registry: Arc<FixtureCarrierRegistry>) -> Self {
        Self { origin, registry }
    }

    fn target(&self, route: &BudgetPeerRoute) -> Result<Arc<BudgetRaftService>, BudgetRpcError> {
        if self.registry.config.voters.get(&route.stable_node_id) != Some(&route.transport_identity)
            || self.registry.config.raft_node_id(&route.stable_node_id) != Some(route.node_id)
        {
            return Err(unreachable_rpc(
                "fixture route is not an exact frozen voter binding",
            ));
        }
        self.registry.target(self.origin, route)
    }

    fn peer(&self) -> Result<AuthenticatedBudgetPeer, BudgetRpcError> {
        self.registry.authenticated_sender(self.origin)
    }
}

#[async_trait]
impl BudgetRaftCarrier for FixtureCarrier {
    async fn submit_budget_command(
        &self,
        route: &BudgetPeerRoute,
        command: super::types::BudgetCommand,
        _deadline: Duration,
    ) -> Result<super::types::BudgetReply, BudgetRpcError> {
        let peer = self.peer()?;
        let reply = self
            .target(route)?
            .command_from_authenticated_peer(&peer, command)
            .await
            .map_err(inbound_rpc)?;
        if self
            .registry
            .take_dropped_command_reply(self.origin, route.node_id)
        {
            return Err(unreachable_rpc(
                "fixture drops a committed client command reply",
            ));
        }
        Ok(reply)
    }

    async fn append_entries(
        &self,
        route: &BudgetPeerRoute,
        request: AppendEntriesRequest<BudgetTypeConfig>,
        _option: RPCOption,
        _deadline: Duration,
    ) -> Result<AppendEntriesResponse<u64>, BudgetRpcError> {
        let peer = self.peer()?;
        self.target(route)?
            .append_entries_from_authenticated_peer(&peer, request)
            .await
            .map_err(inbound_rpc)
    }

    async fn install_snapshot(
        &self,
        route: &BudgetPeerRoute,
        request: InstallSnapshotRequest<BudgetTypeConfig>,
        _option: RPCOption,
        _deadline: Duration,
    ) -> Result<InstallSnapshotResponse<u64>, BudgetSnapshotRpcError> {
        let peer = self
            .peer()
            .map_err(|error| unreachable_snapshot(&error.to_string()))?;
        let target = self
            .target(route)
            .map_err(|error| unreachable_snapshot(&error.to_string()))?;
        target
            .install_snapshot_from_authenticated_peer(&peer, request)
            .await
            .map_err(|error| unreachable_snapshot(&error.to_string()))
    }

    async fn vote(
        &self,
        route: &BudgetPeerRoute,
        request: VoteRequest<u64>,
        _option: RPCOption,
        _deadline: Duration,
    ) -> Result<VoteResponse<u64>, BudgetRpcError> {
        let peer = self.peer()?;
        self.target(route)?
            .vote_from_authenticated_peer(&peer, request)
            .await
            .map_err(inbound_rpc)
    }
}

/// Real OpenRaft/SQLite test fixture shared by budget-domain and provider-leaf
/// tests. It only exists in this `#[cfg(test)]` module.
pub(crate) struct ThreeNodeFixture {
    config: BudgetClusterConfig,
    homes: Vec<TempDir>,
    identities: Vec<LocalNodeIdentity>,
    services: Vec<Arc<BudgetRaftService>>,
    registry: Arc<FixtureCarrierRegistry>,
    carriers: Vec<Arc<FixtureCarrier>>,
    validator: Arc<FixtureMembershipValidator>,
}

impl ThreeNodeFixture {
    async fn start() -> Self {
        Self::start_with_cap(100).await
    }

    /// Starts the immutable three-voter fixture with the requested nanos cap.
    /// Provider tests use a larger cap to keep their accounting input focused.
    pub(crate) async fn start_with_cap(cap_usd_nanos: u64) -> Self {
        let homes = (0..3)
            .map(|_| tempfile::tempdir().unwrap())
            .collect::<Vec<_>>();
        let identities = homes
            .iter()
            .map(|home| LocalNodeIdentity::load_or_create(home.path()).unwrap())
            .collect::<Vec<_>>();
        let voters = identities
            .iter()
            .enumerate()
            .map(|(index, identity)| {
                (
                    identity.stable_node_id().clone(),
                    TransportIdentity::parse(format!("fixture-peeroxide-voter-{index}")).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let config = BudgetClusterConfig::new(
            "w434-three-voter-fixture".into(),
            FIXTURE_EPOCH,
            voters,
            cap_usd_nanos,
            FIXTURE_WINDOW,
        )
        .unwrap();
        let registry = Arc::new(FixtureCarrierRegistry::new(config.clone()));
        let carriers = identities
            .iter()
            .map(|identity| {
                Arc::new(FixtureCarrier::new(
                    config.raft_node_id(identity.stable_node_id()).unwrap(),
                    Arc::clone(&registry),
                ))
            })
            .collect::<Vec<_>>();
        let validator = Arc::new(FixtureMembershipValidator {
            config: config.clone(),
        });
        let mut services = Vec::with_capacity(3);
        for (index, identity) in identities.iter().enumerate() {
            let service = Arc::new(
                BudgetRaftService::recover(
                    homes[index].path(),
                    config.clone(),
                    identity,
                    carriers[index].clone(),
                    validator.clone(),
                )
                .await
                .unwrap(),
            );
            registry.register(
                config.raft_node_id(identity.stable_node_id()).unwrap(),
                &service,
            );
            services.push(service);
        }
        for service in &services {
            service.bootstrap_fixed_voters().await.unwrap();
        }
        let fixture = Self {
            config,
            homes,
            identities,
            services,
            registry,
            carriers,
            validator,
        };
        fixture.wait_for_leader().await;
        fixture
    }

    async fn wait_for_leader(&self) -> u64 {
        tokio::time::timeout(LEADER_WAIT, async {
            loop {
                let mut leaders = BTreeSet::new();
                for service in &self.services {
                    leaders.insert(service.current_leader_node().await);
                }
                if leaders.len() == 1 {
                    if let Some(leader) = *leaders.first().unwrap() {
                        return leader;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("three-node fixture must elect one leader within bound")
    }

    fn service_for(&self, node_id: u64) -> &Arc<BudgetRaftService> {
        let index = self
            .identities
            .iter()
            .position(|identity| {
                self.config.raft_node_id(identity.stable_node_id()) == Some(node_id)
            })
            .unwrap();
        &self.services[index]
    }

    fn node_ids(&self) -> Vec<u64> {
        self.identities
            .iter()
            .map(|identity| self.config.raft_node_id(identity.stable_node_id()).unwrap())
            .collect()
    }

    /// Returns a nonleader replica so callers exercise the authenticated
    /// follower-to-leader budget command route.
    pub(crate) async fn follower_service(&self) -> Arc<BudgetRaftService> {
        let leader = self.wait_for_leader().await;
        self.node_ids()
            .into_iter()
            .find(|node| *node != leader)
            .map(|node| Arc::clone(self.service_for(node)))
            .expect("three-voter fixture must contain a follower")
    }

    /// Cuts every carrier direction between the current leader and both other
    /// voters, leaving the leader without a quorum.
    pub(crate) async fn isolate_leader_both_directions(&self) -> Arc<BudgetRaftService> {
        let leader = self.wait_for_leader().await;
        self.registry
            .isolate_both_directions(leader, self.node_ids());
        Arc::clone(self.service_for(leader))
    }

    fn origin_for(&self, node_id: u64) -> AuthenticatedLocalInvocation {
        let identity = self
            .identities
            .iter()
            .find(|identity| self.config.raft_node_id(identity.stable_node_id()) == Some(node_id))
            .unwrap();
        AuthenticatedLocalInvocation::from_revalidated_local_session(
            identity.stable_node_id().clone(),
            self.config
                .voters
                .get(identity.stable_node_id())
                .unwrap()
                .clone(),
            self.config.membership_epoch,
        )
    }

    fn stable_for(&self, node_id: u64) -> StableNodeId {
        self.identities
            .iter()
            .find(|identity| self.config.raft_node_id(identity.stable_node_id()) == Some(node_id))
            .unwrap()
            .stable_node_id()
            .clone()
    }

    async fn restart(&mut self, node_id: u64) {
        let index = self
            .identities
            .iter()
            .position(|identity| {
                self.config.raft_node_id(identity.stable_node_id()) == Some(node_id)
            })
            .unwrap();
        let previous = self.services.remove(index);
        previous.shutdown().await.unwrap();
        self.registry.remove(node_id);
        drop(previous);
        let replacement = Arc::new(
            BudgetRaftService::recover(
                self.homes[index].path(),
                self.config.clone(),
                &self.identities[index],
                self.carriers[index].clone(),
                self.validator.clone(),
            )
            .await
            .unwrap(),
        );
        self.registry.register(node_id, &replacement);
        self.services.insert(index, replacement);
        self.wait_for_leader().await;
    }

    pub(crate) async fn shutdown(self) {
        for service in &self.services {
            service.shutdown().await.unwrap();
        }
    }
}

fn reserve(config: &BudgetClusterConfig, sequence: u64, nanos: u64) -> ReserveBudget {
    ReserveBudget {
        grant_id: BudgetGrantId(format!("018f0000-0000-7000-8000-{sequence:012x}")),
        provider_intent_id: format!("fixture-intent-{sequence}"),
        request_fingerprint: format!("{sequence:064x}"),
        scope_hash: config.scope_hash.clone(),
        reserved_usd_nanos: nanos,
        utc_window: config.utc_window,
    }
}

fn begin(grant: &super::types::ReservedGrant, owner: &StableNodeId) -> BeginDispatch {
    BeginDispatch {
        grant_id: grant.grant_id.clone(),
        reserve_fence: grant.reserve_fence.clone(),
        owner: owner.clone(),
        attempt_id: DispatchAttemptId(format!("fixture-attempt-{}", grant.grant_id.0)),
        provider_intent_id: grant.provider_intent_id.clone(),
    }
}

fn unreachable_rpc(message: &str) -> BudgetRpcError {
    openraft::error::Unreachable::new(&std::io::Error::other(message.to_owned())).into()
}

fn unreachable_snapshot(message: &str) -> BudgetSnapshotRpcError {
    openraft::error::Unreachable::new(&std::io::Error::other(message.to_owned())).into()
}

fn inbound_rpc(error: BudgetInboundError) -> BudgetRpcError {
    unreachable_rpc(&error.to_string())
}

#[tokio::test]
async fn three_voter_quorum_reserves_claims_once_releases_and_settles() {
    let fixture = ThreeNodeFixture::start().await;
    let leader = fixture.wait_for_leader().await;
    let follower = fixture
        .node_ids()
        .into_iter()
        .find(|node| *node != leader)
        .unwrap();
    let service = fixture.service_for(follower);
    let origin = fixture.origin_for(follower);
    let owner = fixture.stable_for(follower);

    // Reserve -> Begin -> Settle all enter on a follower and traverse the
    // origin-bound carrier to the elected leader exactly once.
    let claim_grant = service
        .reserve(reserve(&fixture.config, 1, 20))
        .await
        .unwrap();
    let claim = begin(&claim_grant, &owner);
    let permit = service
        .begin_dispatch(&origin, claim.clone())
        .await
        .unwrap();
    drop(permit);
    assert!(matches!(
        service.begin_dispatch(&origin, claim).await,
        Err(BudgetServiceError::Unavailable(_))
    ));

    let settle_grant = service
        .reserve(reserve(&fixture.config, 2, 20))
        .await
        .unwrap();
    let settle_permit = service
        .begin_dispatch(&origin, begin(&settle_grant, &owner))
        .await
        .unwrap();
    let settled = service.settle(settle_permit, Some(7)).await.unwrap();
    assert_eq!(settled.grant_id, settle_grant.grant_id);

    let releasable = service
        .reserve(reserve(&fixture.config, 3, 20))
        .await
        .unwrap();
    let released = service
        .release_before_claim(releasable.grant_id.clone(), releasable.reserve_fence)
        .await
        .unwrap();
    assert_eq!(released.grant_id, releasable.grant_id);
    fixture.shutdown().await;
}

#[tokio::test]
async fn concurrent_followers_cannot_overspend_or_reuse_shared_cap() {
    const SHARED_CAP: u64 = 20;
    let mut fixture = ThreeNodeFixture::start_with_cap(SHARED_CAP).await;
    let leader = fixture.wait_for_leader().await;
    let followers = fixture
        .node_ids()
        .into_iter()
        .filter(|node| *node != leader)
        .collect::<Vec<_>>();
    assert_eq!(
        followers.len(),
        2,
        "three voters must leave two live followers"
    );

    let left_node = followers[0];
    let right_node = followers[1];
    let left_request = reserve(&fixture.config, 50, SHARED_CAP);
    let right_request = reserve(&fixture.config, 51, SHARED_CAP);
    let (left, right) = {
        let barrier = Arc::new(Barrier::new(2));
        let left_service = Arc::clone(fixture.service_for(left_node));
        let right_service = Arc::clone(fixture.service_for(right_node));
        let left_barrier = Arc::clone(&barrier);
        let right_barrier = Arc::clone(&barrier);
        let left_attempt = left_request.clone();
        let right_attempt = right_request.clone();
        tokio::join!(
            async move {
                left_barrier.wait().await;
                left_service.reserve(left_attempt).await
            },
            async move {
                right_barrier.wait().await;
                right_service.reserve(right_attempt).await
            },
        )
    };

    let (winner_node, winner_request, winner_grant, loser_node, loser_request) = match (left, right)
    {
        (Ok(grant), Err(BudgetServiceError::Rejected(BudgetRejection::CapExceeded))) => {
            (left_node, left_request, grant, right_node, right_request)
        }
        (Err(BudgetServiceError::Rejected(BudgetRejection::CapExceeded)), Ok(grant)) => {
            (right_node, right_request, grant, left_node, left_request)
        }
        (left, right) => panic!(
            "exactly one concurrent full-cap reservation must commit; left={left:?}, right={right:?}"
        ),
    };
    assert_eq!(winner_grant.grant_id, winner_request.grant_id);
    assert_eq!(winner_grant.reserved_usd_nanos, SHARED_CAP);

    let winner_permit = fixture
        .service_for(winner_node)
        .begin_dispatch(
            &fixture.origin_for(winner_node),
            begin(&winner_grant, &fixture.stable_for(winner_node)),
        )
        .await
        .unwrap();
    assert_eq!(
        winner_permit.claim_receipt().grant_id,
        winner_grant.grant_id
    );
    drop(winner_permit);

    assert!(matches!(
        fixture
            .service_for(loser_node)
            .reserve(loser_request.clone())
            .await,
        Err(BudgetServiceError::Rejected(BudgetRejection::CapExceeded))
    ));
    fixture.restart(loser_node).await;
    assert!(matches!(
        fixture.service_for(loser_node).reserve(loser_request).await,
        Err(BudgetServiceError::Rejected(BudgetRejection::CapExceeded))
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn minority_partition_cannot_commit_a_new_reservation() {
    let fixture = ThreeNodeFixture::start().await;
    let leader = fixture.wait_for_leader().await;
    fixture.registry.block_from(
        leader,
        fixture
            .node_ids()
            .into_iter()
            .filter(|node| *node != leader),
    );
    let blocked = fixture
        .service_for(leader)
        .reserve(reserve(&fixture.config, 10, 20))
        .await;
    assert!(matches!(blocked, Err(BudgetServiceError::Unavailable(_))));

    fixture.registry.heal();
    fixture.wait_for_leader().await;
    let committed = fixture
        .service_for(leader)
        .reserve(reserve(&fixture.config, 10, 20))
        .await
        .unwrap();
    assert_eq!(committed.grant_id.0, "018f0000-0000-7000-8000-00000000000a");
    fixture.shutdown().await;
}

#[tokio::test]
async fn restart_after_discarded_claim_ack_never_reissues_provider_permit() {
    let mut fixture = ThreeNodeFixture::start().await;
    let leader = fixture.wait_for_leader().await;
    let follower = fixture
        .node_ids()
        .into_iter()
        .find(|node| *node != leader)
        .unwrap();
    let service = fixture.service_for(follower);
    let origin = fixture.origin_for(follower);
    let owner = fixture.stable_for(follower);
    let grant = service
        .reserve(reserve(&fixture.config, 20, 20))
        .await
        .unwrap();
    let request = begin(&grant, &owner);
    fixture.registry.drop_next_command_reply(follower, leader);
    assert!(matches!(
        service.begin_dispatch(&origin, request.clone()).await,
        Err(BudgetServiceError::Unavailable(_))
    ));

    fixture.restart(follower).await;
    let recovered = fixture.service_for(follower);
    let recovered_origin = fixture.origin_for(follower);
    assert!(matches!(
        recovered.begin_dispatch(&recovered_origin, request).await,
        Err(BudgetServiceError::Unavailable(_))
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn unknown_and_overrun_settlements_stay_terminal_without_a_new_permit() {
    let fixture = ThreeNodeFixture::start().await;
    let leader = fixture.wait_for_leader().await;
    let follower = fixture
        .node_ids()
        .into_iter()
        .find(|node| *node != leader)
        .unwrap();
    let service = fixture.service_for(follower);
    let origin = fixture.origin_for(follower);
    let owner = fixture.stable_for(follower);

    let unknown_grant = service
        .reserve(reserve(&fixture.config, 30, 20))
        .await
        .unwrap();
    let unknown_permit = service
        .begin_dispatch(&origin, begin(&unknown_grant, &owner))
        .await
        .unwrap();
    let unknown_claim = unknown_permit.claim_receipt();
    drop(unknown_permit);
    let unknown = service
        .settle_reconciliation(unknown_claim.clone(), None)
        .await
        .unwrap();
    assert_eq!(unknown.grant_id, unknown_grant.grant_id);
    assert!(matches!(
        service
            .begin_dispatch(&origin, begin(&unknown_grant, &owner))
            .await,
        Err(BudgetServiceError::Unavailable(_))
    ));

    let overrun_grant = service
        .reserve(reserve(&fixture.config, 31, 20))
        .await
        .unwrap();
    let overrun_permit = service
        .begin_dispatch(&origin, begin(&overrun_grant, &owner))
        .await
        .unwrap();
    let overrun_claim = overrun_permit.claim_receipt();
    assert!(matches!(
        service.settle(overrun_permit, Some(21)).await,
        Err(BudgetServiceError::Rejected(BudgetRejection::Overrun))
    ));
    assert!(matches!(
        service.settle_reconciliation(overrun_claim, Some(21)).await,
        Err(BudgetServiceError::Rejected(BudgetRejection::Overrun))
    ));

    let mut nonexistent_claim = unknown_claim;
    nonexistent_claim.grant_id = BudgetGrantId("018f0000-0000-7000-8000-00000000ffff".into());
    assert!(matches!(
        service
            .settle_reconciliation(nonexistent_claim, Some(1))
            .await,
        Err(BudgetServiceError::Rejected(BudgetRejection::UnknownGrant))
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn changed_membership_origin_cannot_claim_through_a_follower() {
    let fixture = ThreeNodeFixture::start().await;
    let leader = fixture.wait_for_leader().await;
    let follower = fixture
        .node_ids()
        .into_iter()
        .find(|node| *node != leader)
        .unwrap();
    let wrong_origin = fixture
        .node_ids()
        .into_iter()
        .find(|node| *node != leader && *node != follower)
        .unwrap();
    let service = fixture.service_for(follower);
    let grant = service
        .reserve(reserve(&fixture.config, 40, 20))
        .await
        .unwrap();
    assert!(matches!(
        service
            .begin_dispatch(
                &fixture.origin_for(wrong_origin),
                begin(&grant, &fixture.stable_for(follower))
            )
            .await,
        Err(BudgetServiceError::OriginMismatch)
    ));
    fixture.shutdown().await;
}
