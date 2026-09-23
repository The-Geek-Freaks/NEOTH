//! Authenticated Peeroxide transport for the budget OpenRaft authority.
//!
//! The only outbound route is a current `PeerStreamRegistry` generation.  A
//! Raft envelope's claimed sender is never used for routing; it is checked
//! against the current Noise-derived `MembershipGrant` before service ingress.

use super::network::{BudgetPeerRoute, BudgetRaftCarrier, BudgetRpcError, BudgetSnapshotRpcError};
use super::raft_types::BudgetTypeConfig;
use super::service::{AuthenticatedBudgetPeer, BudgetRaftService};
use super::types::{BudgetClusterConfig, BudgetCommand, BudgetReply};
use crate::cluster::heartbeat::{
    BUDGET_RAFT_ENVELOPE_VERSION, BudgetRaftEnvelope, BudgetRaftMessageKind, FrameBody, FrameKind,
    WireFrame, validate_budget_raft_envelope,
};
use crate::cluster::membership::StableNodeId;
use crate::cluster::peer_streams::{BudgetSession, PeerStreamRegistry};
use async_trait::async_trait;
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::sync::{Semaphore, oneshot, watch};

const MAX_PENDING: usize = 64;
const MAX_INBOUND_REQUESTS: usize = 16;

struct PendingReply {
    transport_identity: String,
    stable_node_id: StableNodeId,
    generation: u64,
    expected_kind: BudgetRaftMessageKind,
    reply: oneshot::Sender<BudgetRaftEnvelope>,
}

/// Removes a correlation entry even when OpenRaft drops the carrier future
/// while it awaits a response.  Without this, cancellation could permanently
/// consume one of the bounded 64 pending slots.
struct PendingCleanup<'a> {
    carrier: &'a BudgetPeerCarrier,
    request_id: u64,
}

impl Drop for PendingCleanup<'_> {
    fn drop(&mut self) {
        self.carrier.remove_pending(self.request_id);
    }
}

/// Real Peeroxide carrier.  Both sides use `Weak` references to avoid a
/// registry/carrier/service ownership cycle during runtime shutdown.
pub struct BudgetPeerCarrier {
    registry: Weak<PeerStreamRegistry>,
    service: RwLock<Weak<BudgetRaftService>>,
    config: BudgetClusterConfig,
    local_sender: StableNodeId,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingReply>>,
    stopping: watch::Sender<bool>,
    inbound: Arc<Semaphore>,
}

impl BudgetPeerCarrier {
    pub fn new(
        registry: Weak<PeerStreamRegistry>,
        config: BudgetClusterConfig,
        local_sender: StableNodeId,
    ) -> Arc<Self> {
        let (stopping, _stop_rx) = watch::channel(false);
        Arc::new(Self {
            registry,
            service: RwLock::new(Weak::new()),
            config,
            local_sender,
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            stopping,
            inbound: Arc::new(Semaphore::new(MAX_INBOUND_REQUESTS)),
        })
    }

    /// Called once the recovered service exists. Rebinding replaces only the
    /// weak target and does not grant a carrier a service ownership cycle.
    pub fn bind_service(&self, service: Weak<BudgetRaftService>) {
        *self.service.write().unwrap_or_else(|p| p.into_inner()) = service;
    }

    /// Runtime stop wakes every caller and prevents newly queued ingress.
    pub fn stop(&self) {
        // `send()` with no active receiver reports an error and does not
        // update the watched value. New request subscriptions must observe
        // stopped even when no request was live at the instant of shutdown.
        self.stopping.send_replace(true);
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    pub(crate) fn inbound_session(
        &self,
        registry: &PeerStreamRegistry,
        transport_identity: &str,
        generation: u64,
        grant: &crate::cluster::membership::MembershipGrant,
    ) -> Option<BudgetSession> {
        registry
            .budget_session_for_generation(transport_identity, generation, grant, &self.config)
            .ok()
    }

    fn unavailable(message: &'static str) -> BudgetRpcError {
        openraft::error::Unreachable::new(&std::io::Error::other(message)).into()
    }

    fn snapshot_unavailable(message: &'static str) -> BudgetSnapshotRpcError {
        openraft::error::Unreachable::new(&std::io::Error::other(message)).into()
    }

    fn next_id(&self) -> u64 {
        loop {
            let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    fn envelope(
        &self,
        request_id: u64,
        kind: BudgetRaftMessageKind,
        payload: Vec<u8>,
    ) -> BudgetRaftEnvelope {
        BudgetRaftEnvelope {
            version: BUDGET_RAFT_ENVELOPE_VERSION,
            request_id,
            cluster_id: self.config.cluster_id.clone(),
            membership_epoch: self.config.membership_epoch,
            scope_hash: self.config.scope_hash.0.clone(),
            asserted_sender: self.local_sender.as_str().to_owned(),
            kind,
            payload,
        }
    }

    async fn request(
        &self,
        route: &BudgetPeerRoute,
        kind: BudgetRaftMessageKind,
        expected_kind: BudgetRaftMessageKind,
        payload: Vec<u8>,
        deadline: Duration,
    ) -> Result<BudgetRaftEnvelope, BudgetRpcError> {
        if *self.stopping.borrow() {
            return Err(Self::unavailable("budget carrier is stopping"));
        }
        if route.stable_node_id == self.local_sender {
            return Err(Self::unavailable(
                "budget raft carrier refuses a self route",
            ));
        }
        let Some(registry) = self.registry.upgrade() else {
            return Err(Self::unavailable("budget peer registry is gone"));
        };
        let session = registry
            .budget_session(route, &self.config)
            .map_err(|_| Self::unavailable("no current authenticated budget session"))?;
        let request_id = self.next_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if pending.len() >= MAX_PENDING {
                return Err(Self::unavailable(
                    "budget carrier pending reply limit reached",
                ));
            }
            pending.insert(
                request_id,
                PendingReply {
                    transport_identity: route.transport_identity.as_str().to_owned(),
                    stable_node_id: route.stable_node_id.clone(),
                    generation: session.generation(),
                    expected_kind,
                    reply: tx,
                },
            );
        }
        let _pending_cleanup = PendingCleanup {
            carrier: self,
            request_id,
        };
        let frame = WireFrame {
            kind: FrameKind::BudgetRaft,
            sequence: request_id,
            sent_unix_ms: crate::time::now_unix_i64().max(0) as u64 * 1_000,
            peer_id: self.local_sender.as_str().to_owned(),
            body: FrameBody::BudgetRaft(Box::new(self.envelope(request_id, kind, payload))),
        };
        if registry.send_budget_on_session(&session, frame).is_err() {
            return Err(Self::unavailable(
                "budget request could not enter current authenticated session",
            ));
        }
        let mut cancelled = session.cancellation();
        let mut stopping = self.stopping.subscribe();
        // A stop may race between the first check and subscription. Because a
        // newly subscribed watch receiver only reports later changes through
        // `changed()`, inspect its retained value before entering the select.
        if *stopping.borrow() {
            return Err(Self::unavailable("budget carrier stopped"));
        }
        let result = tokio::select! {
            reply = tokio::time::timeout(deadline, rx) => match reply {
                Ok(Ok(envelope)) => Ok(envelope),
                Ok(Err(_)) => Err(Self::unavailable("budget reply channel was cancelled")),
                Err(_) => Err(Self::unavailable("budget raft request timed out")),
            },
            _ = cancelled.changed() => Err(Self::unavailable("authenticated budget session was cancelled")),
            _ = stopping.changed() => Err(Self::unavailable("budget carrier stopped")),
        };
        result
    }

    fn remove_pending(&self, request_id: u64) {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&request_id);
    }

    /// Called by the Peeroxide connection loop after its ordinary membership
    /// revalidation. Responses correlate synchronously; requests take a
    /// semaphore permit and run in a detached task so the stream can keep
    /// draining responses and never deadlock itself.
    pub(crate) fn accept_envelope(
        self: &Arc<Self>,
        session: BudgetSession,
        envelope: BudgetRaftEnvelope,
    ) {
        if *self.stopping.borrow()
            || validate_budget_raft_envelope(&envelope).is_err()
            || !self.matches_session_config(&session, &envelope)
        {
            return;
        }
        if envelope.kind.is_response() {
            self.accept_response(&session, envelope);
            return;
        }
        // Admit before allocation of a task. A hostile authenticated peer can
        // otherwise create an unbounded number of waiting task futures while
        // all service permits are occupied.
        let Ok(permit) = self.inbound.clone().try_acquire_owned() else {
            return;
        };
        let carrier = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            if *carrier.stopping.borrow() {
                return;
            }
            carrier.handle_request(session, envelope).await;
        });
    }

    fn matches_session_config(
        &self,
        session: &BudgetSession,
        envelope: &BudgetRaftEnvelope,
    ) -> bool {
        envelope.cluster_id == self.config.cluster_id
            && envelope.membership_epoch == self.config.membership_epoch
            && envelope.scope_hash == self.config.scope_hash.0
            && envelope.asserted_sender == session.stable_node_id().as_str()
            && session.grant().membership_epoch().get() == self.config.membership_epoch
            && self.config.voters.get(session.stable_node_id())
                == Some(session.grant().transport_identity())
            && session
                .grant()
                .revalidate(crate::time::now_unix_i64())
                .is_ok()
    }

    fn accept_response(&self, session: &BudgetSession, envelope: BudgetRaftEnvelope) {
        let pending = {
            let mut entries = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let Some(candidate) = entries.get(&envelope.request_id) else {
                return;
            };
            if candidate.transport_identity != session.grant().transport_identity().as_str()
                || candidate.stable_node_id != *session.stable_node_id()
                || candidate.generation != session.generation()
                || candidate.expected_kind != envelope.kind
            {
                return;
            }
            // Do not consume a valid pending request for a mismatched frame;
            // only the exact authenticated tuple may take its reply slot.
            entries.remove(&envelope.request_id)
        };
        let Some(pending) = pending else {
            return;
        };
        let _ = pending.reply.send(envelope);
    }

    async fn handle_request(&self, session: BudgetSession, envelope: BudgetRaftEnvelope) {
        let Some(service) = self
            .service
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .upgrade()
        else {
            return;
        };
        let peer = AuthenticatedBudgetPeer::from_revalidated_peer_session(
            session.stable_node_id().clone(),
            session.grant().transport_identity().clone(),
            session.grant().membership_epoch().get(),
        );
        let (kind, payload) = match envelope.kind {
            BudgetRaftMessageKind::CommandRequest => {
                let Ok(command) = decode::<BudgetCommand>(&envelope.payload) else {
                    return;
                };
                let Ok(reply) = service
                    .command_from_authenticated_peer(&peer, command)
                    .await
                else {
                    return;
                };
                let Ok(payload) = encode(&reply) else {
                    return;
                };
                (BudgetRaftMessageKind::CommandResponse, payload)
            }
            BudgetRaftMessageKind::AppendEntriesRequest => {
                let Ok(request) =
                    decode::<AppendEntriesRequest<BudgetTypeConfig>>(&envelope.payload)
                else {
                    return;
                };
                let Ok(reply) = service
                    .append_entries_from_authenticated_peer(&peer, request)
                    .await
                else {
                    return;
                };
                let Ok(payload) = encode(&reply) else {
                    return;
                };
                (BudgetRaftMessageKind::AppendEntriesResponse, payload)
            }
            BudgetRaftMessageKind::VoteRequest => {
                let Ok(request) = decode::<VoteRequest<u64>>(&envelope.payload) else {
                    return;
                };
                let Ok(reply) = service.vote_from_authenticated_peer(&peer, request).await else {
                    return;
                };
                let Ok(payload) = encode(&reply) else {
                    return;
                };
                (BudgetRaftMessageKind::VoteResponse, payload)
            }
            BudgetRaftMessageKind::InstallSnapshotRequest => {
                let Ok(request) =
                    decode::<InstallSnapshotRequest<BudgetTypeConfig>>(&envelope.payload)
                else {
                    return;
                };
                let Ok(reply) = service
                    .install_snapshot_from_authenticated_peer(&peer, request)
                    .await
                else {
                    return;
                };
                let Ok(payload) = encode(&reply) else {
                    return;
                };
                (BudgetRaftMessageKind::InstallSnapshotResponse, payload)
            }
            _ => return,
        };
        let response = self.envelope(envelope.request_id, kind, payload);
        let frame = WireFrame {
            kind: FrameKind::BudgetRaft,
            sequence: envelope.request_id,
            sent_unix_ms: crate::time::now_unix_i64().max(0) as u64 * 1_000,
            peer_id: self.local_sender.as_str().to_owned(),
            body: FrameBody::BudgetRaft(Box::new(response)),
        };
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let _ = registry.send_budget_on_session(&session, frame);
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output).map_err(|_| ())?;
    if output.len() > crate::cluster::heartbeat::MAX_BUDGET_RAFT_PAYLOAD_BYTES {
        return Err(());
    }
    Ok(output)
}

fn decode<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, ()> {
    if payload.len() > crate::cluster::heartbeat::MAX_BUDGET_RAFT_PAYLOAD_BYTES {
        return Err(());
    }
    ciborium::from_reader(payload).map_err(|_| ())
}

#[async_trait]
impl BudgetRaftCarrier for BudgetPeerCarrier {
    async fn submit_budget_command(
        &self,
        route: &BudgetPeerRoute,
        command: BudgetCommand,
        deadline: Duration,
    ) -> Result<BudgetReply, BudgetRpcError> {
        let payload =
            encode(&command).map_err(|_| Self::unavailable("encode budget command request"))?;
        let reply = self
            .request(
                route,
                BudgetRaftMessageKind::CommandRequest,
                BudgetRaftMessageKind::CommandResponse,
                payload,
                deadline,
            )
            .await?;
        decode(&reply.payload).map_err(|_| Self::unavailable("decode budget command response"))
    }

    async fn append_entries(
        &self,
        route: &BudgetPeerRoute,
        request: AppendEntriesRequest<BudgetTypeConfig>,
        _option: RPCOption,
        deadline: Duration,
    ) -> Result<AppendEntriesResponse<u64>, BudgetRpcError> {
        let payload = encode(&request)
            .map_err(|_| Self::unavailable("encode budget append entries request"))?;
        let reply = self
            .request(
                route,
                BudgetRaftMessageKind::AppendEntriesRequest,
                BudgetRaftMessageKind::AppendEntriesResponse,
                payload,
                deadline,
            )
            .await?;
        decode(&reply.payload)
            .map_err(|_| Self::unavailable("decode budget append entries response"))
    }

    async fn vote(
        &self,
        route: &BudgetPeerRoute,
        request: VoteRequest<u64>,
        _option: RPCOption,
        deadline: Duration,
    ) -> Result<VoteResponse<u64>, BudgetRpcError> {
        let payload =
            encode(&request).map_err(|_| Self::unavailable("encode budget vote request"))?;
        let reply = self
            .request(
                route,
                BudgetRaftMessageKind::VoteRequest,
                BudgetRaftMessageKind::VoteResponse,
                payload,
                deadline,
            )
            .await?;
        decode(&reply.payload).map_err(|_| Self::unavailable("decode budget vote response"))
    }

    async fn install_snapshot(
        &self,
        route: &BudgetPeerRoute,
        request: InstallSnapshotRequest<BudgetTypeConfig>,
        _option: RPCOption,
        deadline: Duration,
    ) -> Result<InstallSnapshotResponse<u64>, BudgetSnapshotRpcError> {
        let payload = encode(&request)
            .map_err(|_| Self::snapshot_unavailable("encode budget snapshot request"))?;
        let reply = self
            .request(
                route,
                BudgetRaftMessageKind::InstallSnapshotRequest,
                BudgetRaftMessageKind::InstallSnapshotResponse,
                payload,
                deadline,
            )
            .await
            .map_err(|_| Self::snapshot_unavailable("budget snapshot request unavailable"))?;
        decode(&reply.payload)
            .map_err(|_| Self::snapshot_unavailable("decode budget snapshot response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::membership::TransportIdentity;
    use std::collections::BTreeMap;

    fn fixture_carrier() -> Arc<BudgetPeerCarrier> {
        let nodes = [
            StableNodeId::parse("11".repeat(32)).unwrap(),
            StableNodeId::parse("22".repeat(32)).unwrap(),
            StableNodeId::parse("33".repeat(32)).unwrap(),
        ];
        let voters = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                (
                    node.clone(),
                    TransportIdentity::parse(format!("peeroxide-{index}")).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let config = BudgetClusterConfig::new("budget-cluster".into(), 1, voters, 100, 1).unwrap();
        BudgetPeerCarrier::new(Weak::new(), config, nodes[0].clone())
    }

    #[test]
    fn stop_is_visible_to_subscribers_created_after_last_receiver_was_dropped() {
        let carrier = fixture_carrier();
        carrier.stop();
        assert!(
            *carrier.stopping.subscribe().borrow(),
            "send_replace must persist stop after the constructor's initial receiver is dropped"
        );
    }

    #[test]
    fn pending_cleanup_releases_slot_when_request_future_is_dropped() {
        let carrier = fixture_carrier();
        let (reply, _receiver) = oneshot::channel();
        carrier.pending.lock().unwrap().insert(
            9,
            PendingReply {
                transport_identity: "peeroxide-1".into(),
                stable_node_id: StableNodeId::parse("22".repeat(32)).unwrap(),
                generation: 3,
                expected_kind: BudgetRaftMessageKind::CommandResponse,
                reply,
            },
        );
        {
            let _cleanup = PendingCleanup {
                carrier: carrier.as_ref(),
                request_id: 9,
            };
        }
        assert!(carrier.pending.lock().unwrap().is_empty());
    }
}
