//! W2309 candidate — daemon-owned v3 mobile companion runtime.
//!
//! The runtime deliberately sits between the R4 protocol/authority and the
//! existing reviewed Peeroxide rendezvous boundary.  It owns the durable server
//! Noise seed, one daemon boot identity, all P2P listener tasks and the only
//! WAL reconciliation call.  CLI processes only use the same-user audit RPC;
//! they never mint a QR with an unknown responder key or open a second writer.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock, oneshot, watch};
use uuid::Uuid;

use crate::{
    daemon::{
        chat_runtime::{CompanionChatTurnError, DaemonChatRuntime},
        companion_authority::{
            AuditObservation, DeviceAuthority, DeviceGrant, MutationKind, PendingAudit, Reconcile,
            StatusLease,
        },
        companion_protocol::{
            COMPANION_V3_SCHEMA_VERSION, ChatChallenge, CompanionChatOutcome, CompanionChatRecord,
            CompanionChatRecordKind, CompanionChatRequest, CompanionChatTerminal, CompanionDenied,
            CompanionDeniedCode, CompanionDeviceId, CompanionReadiness, CompanionScope,
            CompanionStatusSnapshot, EnrollmentAccepted, EnrollmentProof, ReconnectDescriptor,
            ServerFrame, StatusProof,
        },
    },
    wal::{
        companion_mutation_receipts::{
            CompanionMutationReceiptDescriptor, CompanionMutationReceiptOutcome,
        },
        writer::WalWriterHandle,
    },
};

const SERVER_KEY_FILE: &str = "companion-v3-server-noise.json";
const SERVER_KEY_LOCK: &str = "companion-v3-server-noise.lock";
const INVITE_TTL_SECS: u64 = 300;
const CONNECTION_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const ACTIVE_LISTENER_READINESS_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DEVICE_LISTENERS: usize = 128;

type PairListenerReadiness = std::result::Result<(), String>;

#[cfg(test)]
pub(crate) enum AuditPairReadinessTestOutcome {
    RefusedAfterOwnerSpawn,
    UncertainAfterOwnerSpawn,
}

enum PairReadinessWait {
    Discovery(Result<()>),
    CallerCancelled,
}

async fn wait_for_pair_readiness_or_caller_drop(
    readiness: impl std::future::Future<Output = Result<()>>,
    sender: &mut oneshot::Sender<PairListenerReadiness>,
) -> PairReadinessWait {
    tokio::select! {
        result = readiness => PairReadinessWait::Discovery(result),
        _ = sender.closed() => PairReadinessWait::CallerCancelled,
    }
}

fn report_pair_readiness(
    sender: &mut Option<oneshot::Sender<PairListenerReadiness>>,
    result: PairListenerReadiness,
) -> bool {
    sender
        .take()
        .is_none_or(|sender| sender.send(result).is_ok())
}

/// A status reply is not a detached timeout future.  This owner retains the
/// lease, connection and rendezvous actor until it can classify both the
/// actual write and the checked Peeroxide teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusDeliveryTerminal {
    WriteCompletedAndTeardownConfirmed,
    CancelledBeforeWriteAndTeardownConfirmed,
    WriteFailedAndTeardownConfirmed,
    /// The peer write or Peeroxide actor drain cannot be proven. The durable
    /// authority write-ahead marker remains present when this lease drops.
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalDeliveryState {
    NoWriteStarted,
    WriteCompleted,
    WriteFailed,
}

/// A checked carrier drain is the local terminal proof. It does not claim a
/// remote undo or remote observation of a successfully written frame.
fn local_carrier_terminal(state: LocalDeliveryState, teardown_confirmed: bool) -> bool {
    teardown_confirmed
        && matches!(
            state,
            LocalDeliveryState::NoWriteStarted
                | LocalDeliveryState::WriteCompleted
                | LocalDeliveryState::WriteFailed
        )
}

struct StatusDelivery {
    task: tokio::task::JoinHandle<Result<StatusDeliveryTerminal>>,
}

/// One cancellation sender and one join handle share a single registry entry.
/// Reserving the entry before spawning prevents a second listener for the same
/// device without ever holding two async mutexes across an await.
struct DeviceListenerOwner {
    stop_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

struct PairListenerOwner {
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl StatusDelivery {
    fn spawn(
        lease: StatusLease,
        snapshot: CompanionStatusSnapshot,
        mut connection: peeroxide::SwarmConnection,
        rendezvous: crate::cluster::hyperswarm::SharedPublicRendezvous,
        shutdown: watch::Receiver<bool>,
        readiness: Arc<RwLock<CompanionReadiness>>,
    ) -> Self {
        let task = tokio::spawn(async move {
            // The lease, accepted connection and carrier stay in this one task
            // until both the actual write and checked actor drain are known.
            let frame = match lease.status_frame(snapshot) {
                Ok(frame) => frame,
                Err(error) => {
                    tracing::warn!(%error, "companion v3 status frame could not be serialized");
                    drop(connection);
                    if !local_carrier_terminal(
                        LocalDeliveryState::NoWriteStarted,
                        rendezvous.shutdown_checked().await.is_ok(),
                    ) || lease.complete_confirmed().is_err()
                    {
                        *readiness.write().await = CompanionReadiness::Degraded;
                        drop(lease);
                        return Ok(StatusDeliveryTerminal::Indeterminate);
                    }
                    drop(lease);
                    return Ok(StatusDeliveryTerminal::CancelledBeforeWriteAndTeardownConfirmed);
                }
            };
            if *shutdown.borrow() {
                drop(connection);
                if !local_carrier_terminal(
                    LocalDeliveryState::NoWriteStarted,
                    rendezvous.shutdown_checked().await.is_ok(),
                ) {
                    *readiness.write().await = CompanionReadiness::Degraded;
                    drop(lease);
                    return Ok(StatusDeliveryTerminal::Indeterminate);
                }
                // Retain the lease through carrier drain: revocation cannot
                // finalize while delivery cleanup remains uncertain.
                if lease.complete_confirmed().is_err() {
                    *readiness.write().await = CompanionReadiness::Degraded;
                    drop(lease);
                    return Ok(StatusDeliveryTerminal::Indeterminate);
                }
                drop(lease);
                return Ok(StatusDeliveryTerminal::CancelledBeforeWriteAndTeardownConfirmed);
            }

            // Never cancel an in-flight Peeroxide write with timeout/select.
            // Shutdown is checked before this effect, then joins its owner.
            let write = connection
                .write(&frame)
                .await
                .context("companion v3 status snapshot write");
            drop(connection);
            let teardown = rendezvous.shutdown_checked().await;
            let delivery_state = if write.is_ok() {
                LocalDeliveryState::WriteCompleted
            } else {
                LocalDeliveryState::WriteFailed
            };
            if !local_carrier_terminal(delivery_state, teardown.is_ok()) {
                // Actor drain is unproven, so retain the durable marker.
                *readiness.write().await = CompanionReadiness::Degraded;
                drop(lease);
                return Ok(StatusDeliveryTerminal::Indeterminate);
            }
            if delivery_state == LocalDeliveryState::WriteFailed {
                // The write future has completed with a local terminal error,
                // the connection is dropped and the actor drain is checked:
                // this proves no further local delivery can occur. It says
                // nothing about a remote retraction or observed result.
                if lease.complete_confirmed().is_err() {
                    *readiness.write().await = CompanionReadiness::Degraded;
                    drop(lease);
                    return Ok(StatusDeliveryTerminal::Indeterminate);
                }
                drop(lease);
                return Ok(StatusDeliveryTerminal::WriteFailedAndTeardownConfirmed);
            }
            // This is the only completion path: the authority writes its
            // durable terminal confirmation after both observable effects.
            if let Err(error) = lease.complete_confirmed() {
                tracing::warn!(%error, "companion status delivery confirmation was not durable");
                *readiness.write().await = CompanionReadiness::Degraded;
                drop(lease);
                return Ok(StatusDeliveryTerminal::Indeterminate);
            }
            drop(lease);
            Ok(StatusDeliveryTerminal::WriteCompletedAndTeardownConfirmed)
        });
        Self { task }
    }

    async fn join(self) -> Result<StatusDeliveryTerminal> {
        self.task
            .await
            .context("companion status delivery task panicked")?
    }
}

/// Private state stored before a v3 QR is emitted.  `seed` is never serialized
/// into a QR, WAL record, RPC reply or tracing field.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerKeyRecord {
    schema_version: u8,
    seed: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompanionV3Invite {
    pub(crate) schema_version: u8,
    pub(crate) pair_url: String,
    pub(crate) expires_in_secs: u64,
    pub(crate) requested_scope: CompanionScope,
}

/// A ready listener is held privately until the authenticated RPC owner has
/// written its QR response.  Dropping this value does not detach the listener:
/// the owner must either publish the response or call
/// `cancel_prepared_pair_invite` and await the exact task terminal.
pub(crate) struct PreparedCompanionV3Invite {
    invite: CompanionV3Invite,
    pair_task_key: String,
}

/// Audit-RPC may keep its listener alive after a pairing readiness refusal only
/// when the runtime proved that it left no newly-created listener owner behind.
pub(crate) enum AuditPairInvitePreparation {
    Prepared(PreparedCompanionV3Invite),
    Refused,
}

enum PairListenerPreparation {
    Ready(ReadyPairListener),
    Refused,
}

impl PreparedCompanionV3Invite {
    pub(crate) fn invite(&self) -> &CompanionV3Invite {
        &self.invite
    }
}

struct ReadyPairListener {
    remaining_ttl_secs: u64,
    pair_task_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompanionV3DeviceView {
    pub(crate) device_id: CompanionDeviceId,
    pub(crate) label: String,
    pub(crate) revision: u64,
    pub(crate) grant_state: String,
}

#[derive(Clone)]
pub(crate) struct CompanionRuntime {
    home: PathBuf,
    authority: Arc<DeviceAuthority>,
    chat_runtime: Arc<DaemonChatRuntime>,
    writer: WalWriterHandle,
    daemon_key: peeroxide::KeyPair,
    daemon_boot_id: String,
    listener_generation: u64,
    readiness: Arc<RwLock<CompanionReadiness>>,
    shutdown_tx: watch::Sender<bool>,
    public_carrier:
        Arc<Mutex<Option<Arc<crate::cluster::hyperswarm::SharedPublicRendezvousCarrier>>>>,
    pair_tasks: Arc<Mutex<BTreeMap<String, PairListenerOwner>>>,
    listener_tasks: Arc<Mutex<BTreeMap<Uuid, DeviceListenerOwner>>>,
    #[cfg(test)]
    next_audit_pair_readiness: Arc<Mutex<Option<AuditPairReadinessTestOutcome>>>,
}

impl CompanionRuntime {
    /// Constructing this runtime first reads/creates the private server seed.
    /// Therefore every QR emitted by this daemon contains the public key that
    /// the subsequent Peeroxide responder actually uses.
    pub(crate) fn load(
        home: PathBuf,
        writer: WalWriterHandle,
        chat_runtime: Arc<DaemonChatRuntime>,
        daemon_boot_id: String,
        listener_generation: u64,
    ) -> Result<Arc<Self>> {
        anyhow::ensure!(
            !daemon_boot_id.is_empty() && listener_generation > 0,
            "invalid daemon companion generation"
        );
        let daemon_key = load_or_create_server_key(&home)?;
        let authority = Arc::new(DeviceAuthority::load(&home)?);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Ok(Arc::new(Self {
            home,
            authority,
            chat_runtime,
            writer,
            daemon_key,
            daemon_boot_id,
            listener_generation,
            readiness: Arc::new(RwLock::new(CompanionReadiness::Starting)),
            shutdown_tx,
            public_carrier: Arc::new(Mutex::new(None)),
            pair_tasks: Arc::new(Mutex::new(BTreeMap::new())),
            listener_tasks: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(test)]
            next_audit_pair_readiness: Arc::new(Mutex::new(None)),
        }))
    }

    pub(crate) async fn start(self: &Arc<Self>) -> Result<()> {
        // A pending durable authority transition is never guessed from a
        // queued append.  The typed WAL helper authenticates the exact ID and
        // returns ExistingExact/AppendedExact before authority finalization.
        for pending in self.authority.pending_audits()? {
            self.complete_pending_audit(pending).await?;
        }
        for device in self.authority.list()? {
            self.spawn_active_listener(device).await?;
        }
        *self.readiness.write().await = CompanionReadiness::Ready;
        Ok(())
    }

    pub(crate) async fn shutdown_and_drain(&self) -> Result<()> {
        // Persist shutdown before taking task ownership: a retained pair task
        // can subscribe only after this call, and must still observe stop.
        request_runtime_shutdown(&self.shutdown_tx);
        // Take ownership before joining; no mutex is held across a listener
        // await, so every carrier can observe cancellation and drain before
        // the final WAL sender is released.
        let pairs = std::mem::take(&mut *self.pair_tasks.lock().await);
        let mut first_error = None;
        for (_, owner) in pairs {
            owner.stop_tx.send_replace(true);
            if let Err(error) = join_companion_task(owner.task, "pair listener").await {
                first_error.get_or_insert(error);
            }
        }
        let tasks = std::mem::take(&mut *self.listener_tasks.lock().await);
        for (_, owner) in &tasks {
            if let Err(error) = signal_listener_stop(owner, "runtime shutdown") {
                first_error.get_or_insert(error);
            }
        }
        for (_, owner) in tasks {
            if let Some(task) = owner.task {
                if let Err(error) = join_companion_task(task, "device listener").await {
                    first_error.get_or_insert(error);
                }
            } else {
                first_error.get_or_insert_with(|| anyhow::anyhow!(
                    "companion runtime shutdown could not prove device listener terminal: missing join handle"
                ));
            }
        }
        if let Some(carrier) = self.public_carrier.lock().await.take()
            && let Err(error) = carrier.shutdown_checked().await
        {
            first_error.get_or_insert(error);
        }
        if let Some(error) = first_error {
            self.mark_degraded().await;
            return Err(error);
        }
        Ok(())
    }

    async fn shared_public_carrier(
        &self,
    ) -> Result<Arc<crate::cluster::hyperswarm::SharedPublicRendezvousCarrier>> {
        let mut carrier = self.public_carrier.lock().await;
        if let Some(carrier) = carrier.as_ref() {
            return Ok(Arc::clone(carrier));
        }
        let started = crate::cluster::hyperswarm::spawn_shared_public_rendezvous_carrier(
            self.daemon_key.clone(),
            tokio::time::Instant::now() + ACTIVE_LISTENER_READINESS_TIMEOUT,
            self.shutdown_tx.subscribe(),
        )
        .await?;
        *carrier = Some(Arc::clone(&started));
        Ok(started)
    }

    pub(crate) async fn prepare_pair_invite_for_audit_rpc(
        self: &Arc<Self>,
        requested_scope: CompanionScope,
        readiness_budget: Duration,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<AuditPairInvitePreparation> {
        let mut topic = [0u8; 32];
        let mut psk = [0u8; 16];
        getrandom::getrandom(&mut topic).context("mint companion v3 topic")?;
        getrandom::getrandom(&mut psk).context("mint companion v3 psk")?;
        let minted_at = tokio::time::Instant::now();
        let invite_deadline = minted_at + Duration::from_secs(INVITE_TTL_SECS);
        let readiness_deadline =
            minted_at + readiness_budget.min(Duration::from_secs(INVITE_TTL_SECS));
        let preparation = self
            .spawn_pair_listener(
                topic,
                psk,
                requested_scope,
                invite_deadline,
                readiness_deadline,
                cancellation,
            )
            .await?;
        let PairListenerPreparation::Ready(ready_listener) = preparation else {
            return Ok(AuditPairInvitePreparation::Refused);
        };
        let url = build_pair_url(
            topic,
            psk,
            self.daemon_key.public_key,
            ready_listener.remaining_ttl_secs,
            requested_scope,
        );
        Ok(AuditPairInvitePreparation::Prepared(
            PreparedCompanionV3Invite {
                invite: CompanionV3Invite {
                    schema_version: COMPANION_V3_SCHEMA_VERSION,
                    pair_url: url,
                    expires_in_secs: ready_listener.remaining_ttl_secs,
                    requested_scope,
                },
                pair_task_key: ready_listener.pair_task_key,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) async fn set_next_audit_pair_readiness_for_test(
        &self,
        outcome: AuditPairReadinessTestOutcome,
    ) {
        *self.next_audit_pair_readiness.lock().await = Some(outcome);
    }

    #[cfg(test)]
    pub(crate) async fn audit_pair_owner_count_for_test(&self) -> usize {
        self.pair_tasks.lock().await.len()
    }

    pub(crate) async fn cancel_prepared_pair_invite(
        &self,
        prepared: PreparedCompanionV3Invite,
    ) -> Result<()> {
        self.join_failed_pair_listener(&prepared.pair_task_key)
            .await
    }

    pub(crate) fn publish_prepared_pair_invite(
        &self,
        prepared: PreparedCompanionV3Invite,
    ) -> CompanionV3Invite {
        prepared.invite
    }

    async fn spawn_pair_listener(
        self: &Arc<Self>,
        topic: [u8; 32],
        psk: [u8; 16],
        requested_scope: CompanionScope,
        invite_deadline: tokio::time::Instant,
        readiness_deadline: tokio::time::Instant,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<PairListenerPreparation> {
        self.reap_finished_pair_tasks().await?;
        let key = hex::encode(topic);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (pair_stop_tx, pair_stop_rx) = watch::channel(false);
        #[cfg(test)]
        let fixture_readiness = self.next_audit_pair_readiness.lock().await.take();
        {
            let mut tasks = self.pair_tasks.lock().await;
            if tasks.len() >= MAX_DEVICE_LISTENERS || tasks.contains_key(&key) {
                return Ok(PairListenerPreparation::Refused);
            }
            let runtime = Arc::clone(self);
            let task = tokio::spawn(async move {
                #[cfg(test)]
                if let Some(fixture) = fixture_readiness {
                    return match fixture {
                        AuditPairReadinessTestOutcome::RefusedAfterOwnerSpawn => {
                            let _ =
                                ready_tx.send(Err("fixture checked readiness refusal".to_owned()));
                            Ok(())
                        }
                        AuditPairReadinessTestOutcome::UncertainAfterOwnerSpawn => {
                            let _ = ready_tx.send(Err("fixture teardown uncertainty".to_owned()));
                            anyhow::bail!("fixture pair listener teardown uncertainty")
                        }
                    };
                }
                runtime
                    .run_pair_listener_until_ready(
                        topic,
                        psk,
                        requested_scope,
                        invite_deadline,
                        Some(ready_tx),
                        pair_stop_rx,
                    )
                    .await
            });
            tasks.insert(
                key.clone(),
                PairListenerOwner {
                    stop_tx: pair_stop_tx.clone(),
                    task,
                },
            );
        }

        if *cancellation.borrow() {
            drop(ready_rx);
            self.join_failed_pair_listener(&key).await?;
            anyhow::bail!("companion pair mint was cancelled before readiness")
        }

        tokio::select! {
            readiness = ready_rx => match readiness {
            Ok(Ok(())) if !*cancellation.borrow() => {
                match remaining_pair_invite_ttl(invite_deadline) {
                    Ok(remaining_ttl_secs) => Ok(PairListenerPreparation::Ready(ReadyPairListener {
                        remaining_ttl_secs,
                        pair_task_key: key.clone(),
                    })),
                    Err(error) => {
                        self.join_failed_pair_listener(&key).await?;
                        Err(error)
                    }
                }
            }
            Ok(Ok(())) => {
                self.join_failed_pair_listener(&key).await?;
                anyhow::bail!("companion pair mint was cancelled before publication")
            }
            Ok(Err(message)) => {
                match self.join_proven_refused_pair_listener(&key).await {
                    Ok(()) => Ok(PairListenerPreparation::Refused),
                    Err(error) => Err(error.context(format!(
                        "companion pair listener readiness was unproven: {message}"
                    ))),
                }
            }
            Err(_) => {
                self.join_failed_pair_listener(&key).await?;
                anyhow::bail!("companion pair listener ended before readiness")
            }
            },
            changed = cancellation.changed() => {
                let _ = changed;
                self.join_failed_pair_listener(&key).await?;
                anyhow::bail!("companion pair mint was cancelled before readiness")
            }
            _ = tokio::time::sleep_until(readiness_deadline) => {
                self.join_failed_pair_listener(&key).await?;
                anyhow::bail!("companion pair mint deadline expired before readiness")
            }
        }
    }

    async fn join_proven_refused_pair_listener(&self, key: &str) -> Result<()> {
        let owner =
            self.pair_tasks.lock().await.remove(key).with_context(
                || "unready pair listener owner disappeared before its terminal join",
            )?;
        owner.stop_tx.send_replace(true);
        match owner
            .task
            .await
            .with_context(|| "unready pair listener task panicked or was cancelled")?
        {
            Ok(()) => Ok(()),
            Err(error) => Err(error.context("unready pair listener terminal was unproven")),
        }
    }

    async fn join_failed_pair_listener(&self, key: &str) -> Result<()> {
        let owner = self.pair_tasks.lock().await.remove(key);
        if let Some(owner) = owner {
            owner.stop_tx.send_replace(true);
            join_companion_task(owner.task, "unready pair listener").await?;
        }
        Ok(())
    }

    async fn run_pair_listener(
        self: &Arc<Self>,
        topic: [u8; 32],
        psk: [u8; 16],
        requested_scope: CompanionScope,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(INVITE_TTL_SECS);
        let (_pair_stop_tx, pair_stop_rx) = watch::channel(false);
        self.run_pair_listener_until_ready(
            topic,
            psk,
            requested_scope,
            deadline,
            None,
            pair_stop_rx,
        )
        .await
    }

    async fn run_pair_listener_until_ready(
        self: &Arc<Self>,
        topic: [u8; 32],
        psk: [u8; 16],
        requested_scope: CompanionScope,
        deadline: tokio::time::Instant,
        mut readiness_tx: Option<oneshot::Sender<PairListenerReadiness>>,
        mut pair_stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let expected_client_noise = invite_client_noise_key(&topic, &psk);
        let mut shutdown = self.shutdown_tx.subscribe();
        if *shutdown.borrow() || *pair_stop.borrow() {
            report_pair_readiness(
                &mut readiness_tx,
                Err("companion runtime is already shutting down".to_owned()),
            );
            anyhow::bail!("companion runtime is already shutting down")
        }
        let mut diagnostics = CompanionPairDiagnostics::from_environment();
        diagnostics.phase("bootstrap_started");
        let carrier = self.shared_public_carrier().await?;
        let mut rendezvous = match carrier
            .open_route(
                topic,
                expected_client_noise,
                deadline,
                shutdown.clone(),
                Some(&mut pair_stop),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                diagnostics.failed("bootstrap_started");
                report_pair_readiness(&mut readiness_tx, Err(error.to_string()));
                return Err(error);
            }
        };
        diagnostics.phase("rendezvous_started");
        diagnostics.phase("initial_discovery_started");

        let readiness = if let Some(sender) = readiness_tx.as_mut() {
            wait_for_pair_readiness_or_caller_drop(
                rendezvous.wait_for_initial_discovery_until_stop(
                    &mut shutdown,
                    Some(&mut pair_stop),
                    deadline,
                ),
                sender,
            )
            .await
        } else {
            tokio::select! {
                discovery = rendezvous.wait_for_initial_discovery(&mut shutdown, deadline) => {
                    PairReadinessWait::Discovery(discovery)
                }
                _ = pair_stop.changed() => PairReadinessWait::CallerCancelled,
            }
        };
        match readiness {
            PairReadinessWait::Discovery(Ok(())) => {
                if !report_pair_readiness(&mut readiness_tx, Ok(())) {
                    return rendezvous.shutdown_checked().await;
                }
            }
            PairReadinessWait::Discovery(Err(error)) => {
                let message = error.to_string();
                let teardown = rendezvous.shutdown_checked().await;
                match teardown {
                    Ok(()) => {
                        report_pair_readiness(&mut readiness_tx, Err(message));
                        return Ok(());
                    }
                    Err(teardown_error) => {
                        report_pair_readiness(&mut readiness_tx, Err(message));
                        return Err(
                            teardown_error.context("unready companion pair listener teardown")
                        );
                    }
                }
            }
            PairReadinessWait::CallerCancelled => {
                return rendezvous.shutdown_checked().await;
            }
        }

        // Initial discovery has terminated before QR publication. This is not
        // a claim that announcement succeeded or a client will observe it.
        diagnostics.phase("bootstrap_ready");
        diagnostics.phase("topic_joined");
        let result = async {
            diagnostics.phase("awaiting_connection");
            loop {
                let next = tokio::select! {
                    biased;
                    _ = shutdown.changed() => None,
                    _ = pair_stop.changed() => None,
                    _ = tokio::time::sleep_until(deadline) => None,
                    next = rendezvous.recv() => next,
                };
                let Some(mut connection) = next else { break; };
                diagnostics.phase("connection_received");
                if connection.is_initiator { continue; }
                let observed_noise = *connection.remote_public_key();
                let raw_psk = tokio::time::timeout(CONNECTION_FRAME_TIMEOUT, connection.read()).await
                    .context("v3 pair psk read timeout")??.context("v3 pair closed before psk")?;
                if !constant_time_eq(&raw_psk, &psk) { continue; }
                diagnostics.phase("psk_verified");
                let proof: EnrollmentProof = read_frame(&mut connection).await?;
                diagnostics.phase("proof_read");
                let accepted = match self
                    .enroll_after_verified_pairing(
                        proof,
                        observed_noise,
                        topic,
                        requested_scope,
                        &mut diagnostics,
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        let denied = ServerFrame::Denied(CompanionDenied::new(CompanionDeniedCode::DeviceDenied)?);
                        if let Err(denial_error) = write_frame(&mut connection, &denied).await {
                            tracing::warn!(%denial_error, "companion pairing denial was not delivered");
                            return Err(denial_error.context("pairing denied and denial frame was unverified"));
                        }
                        return Err(error);
                    }
                };
                // Keep this exact Pair admission live through the terminal
                // EnrollmentAccepted frame.  A mobile retry can legitimately
                // replay the authenticated DHT handshake while this response
                // owner still owns the reply; withdrawing the topic here
                // would turn that retry into an un-routable terminal loss.
                diagnostics.phase("enrollment_response_write_started");
                write_frame(&mut connection, &ServerFrame::EnrollmentAccepted(accepted)).await?;
                diagnostics.phase("response_written");
                break;
            }
            Ok(())
        }.await;
        let failure_phase = result.as_ref().err().map(|_| diagnostics.last_phase());
        diagnostics.phase("teardown_started");
        let teardown = rendezvous.shutdown_checked().await;
        if result.is_err() {
            diagnostics.failed(failure_phase.unwrap_or("unknown"));
        }
        match teardown {
            Ok(()) => diagnostics.phase("teardown_completed"),
            Err(_) => diagnostics.phase("teardown_failed"),
        }
        result?;
        teardown
    }

    pub(crate) fn list_devices(&self) -> Result<Vec<CompanionV3DeviceView>> {
        self.authority
            .list()?
            .into_iter()
            .map(device_view)
            .collect()
    }

    pub(crate) async fn revoke_device(&self, device_id: CompanionDeviceId) -> Result<bool> {
        // Refuse obvious invalid phase transitions before publishing a new
        // mutation. The deny must be durable before the owned listener sees a
        // stop signal: otherwise an accepted chat can start between cancel and
        // PendingRevoke.
        let grant = self.authority.device(&device_id)?;
        if grant.phase_name() != "active" {
            return Ok(false);
        }
        let Some(pending) = self
            .authority
            .begin_revoke_pending_after_effect_boundary(&device_id)
            .await?
        else {
            return Ok(false);
        };
        let stop_result = {
            let tasks = self.listener_tasks.lock().await;
            match tasks.get(&device_id.0) {
                Some(owner) => signal_listener_stop(owner, "device revoke"),
                None => Ok(()),
            }
        };
        if let Err(error) = stop_result {
            self.mark_degraded().await;
            return Err(error);
        }
        let owner = self.listener_tasks.lock().await.remove(&device_id.0);
        if let Some(owner) = owner {
            if let Some(task) = owner.task {
                if let Err(error) = join_companion_task(task, "revoked device listener").await {
                    self.mark_degraded().await;
                    return Err(error);
                }
            } else {
                self.mark_degraded().await;
                anyhow::bail!(
                    "companion revoke could not prove listener terminal: missing join handle"
                );
            }
        } else {
            self.mark_degraded().await;
            anyhow::bail!("companion revoke lost its owned listener before drain proof");
        }
        // The joined owner has completed (or conclusively failed) every
        // connection it accepted. Keep PendingRevoke if its lease counter
        // cannot reach zero; that failure is never converted into a WAL
        // finalization.
        if let Err(error) = self.authority.wait_for_revoke_drain(&device_id).await {
            self.mark_degraded().await;
            return Err(error.context("revoked device lease drain was not proven"));
        }
        // Do not finalize the durable revoke audit before the owned listener
        // has proved its terminal state; a failed join leaves PendingRevoke.
        self.complete_pending_audit(pending).await?;
        Ok(true)
    }

    async fn complete_pending_audit(&self, pending: PendingAudit) -> Result<()> {
        let descriptor = CompanionMutationReceiptDescriptor {
            schema_version: 1,
            mutation_id: pending.mutation_id,
            device_id: pending.device_id.0,
            revision: pending.revision,
            kind: match pending.kind {
                MutationKind::Enroll => {
                    crate::wal::companion_mutation_receipts::CompanionMutationKind::Enroll
                }
                MutationKind::Revoke => {
                    crate::wal::companion_mutation_receipts::CompanionMutationKind::Revoke
                }
            },
            key_sha256: pending.key_sha256.clone(),
        };
        match self
            .writer
            .append_companion_mutation_receipt_once(&self.home, descriptor)
            .await
            .map_err(|error| match error {
                crate::wal::companion_mutation_receipts::CompanionMutationReceiptError::Conflict => {
                    anyhow::anyhow!("companion mutation receipt conflicts with durable state")
                }
                crate::wal::companion_mutation_receipts::CompanionMutationReceiptError::Duplicate => {
                    anyhow::anyhow!("companion mutation receipt duplicate was not exact")
                }
                crate::wal::companion_mutation_receipts::CompanionMutationReceiptError::Indeterminate => {
                    anyhow::anyhow!("companion mutation receipt durability is indeterminate")
                }
            })?
        {
            CompanionMutationReceiptOutcome::ExistingExact
            | CompanionMutationReceiptOutcome::AppendedExact => {}
        }
        match self
            .authority
            .reconcile_audit(pending.mutation_id, AuditObservation::Observed)?
        {
            Reconcile::Finalized(_) | Reconcile::AlreadyFinalized => Ok(()),
            Reconcile::Append(_) => anyhow::bail!("exact companion WAL receipt was not finalized"),
        }
    }

    async fn spawn_active_listener(self: &Arc<Self>, grant: DeviceGrant) -> Result<()> {
        if grant.phase_name() != "active" {
            return Ok(());
        }
        let device_id = grant.device_id.0;
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = oneshot::channel::<PairListenerReadiness>();
        {
            let mut tasks = self.listener_tasks.lock().await;
            if tasks.contains_key(&device_id) {
                return Ok(());
            }
            anyhow::ensure!(
                tasks.len() < MAX_DEVICE_LISTENERS,
                "companion listener cap reached"
            );
            tasks.insert(
                device_id,
                DeviceListenerOwner {
                    stop_tx,
                    task: None,
                },
            );
        }
        let runtime = Arc::clone(self);
        let task = tokio::spawn(async move {
            runtime
                .run_device_listener(grant, stop_rx, Some(ready_tx))
                .await
        });
        let mut task = Some(task);
        if let Some(owner) = self.listener_tasks.lock().await.get_mut(&device_id) {
            owner.task = task.take();
        }
        if let Some(task) = task {
            // The reserved owner exited before its handle was installed. Its
            // sender was dropped, so the listener observes cancellation; join
            // it here rather than silently detaching a live carrier task.
            join_companion_task(task, "early-exited device listener").await?;
        }
        match ready_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(message)) => anyhow::bail!(
                "companion active listener was not ready before descriptor publication: {message}"
            ),
            Err(_) => anyhow::bail!(
                "companion active listener ended before descriptor publication readiness"
            ),
        }
    }

    async fn reap_finished_pair_tasks(&self) -> Result<()> {
        let finished = {
            let mut tasks = self.pair_tasks.lock().await;
            let keys = tasks
                .iter()
                .filter_map(|(key, owner)| owner.task.is_finished().then(|| key.clone()))
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| tasks.remove(&key))
                .collect::<Vec<_>>()
        };
        for owner in finished {
            owner.stop_tx.send_replace(true);
            if let Err(error) = join_companion_task(owner.task, "completed pair listener").await {
                self.mark_degraded().await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn mark_degraded(&self) {
        *self.readiness.write().await = CompanionReadiness::Degraded;
    }

    async fn run_device_listener(
        self: Arc<Self>,
        grant: DeviceGrant,
        mut device_stop: watch::Receiver<bool>,
        mut readiness_tx: Option<oneshot::Sender<PairListenerReadiness>>,
    ) -> Result<()> {
        let topic = grant.reconnect.rendezvous_topic;
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            if listener_stop_requested(&shutdown, &device_stop) {
                break;
            }
            let readiness_deadline =
                tokio::time::Instant::now() + ACTIVE_LISTENER_READINESS_TIMEOUT;
            let carrier = self.shared_public_carrier().await?;
            let mut rendezvous = match carrier
                .open_route(
                    topic,
                    grant.client_noise_key,
                    readiness_deadline,
                    shutdown.clone(),
                    None,
                )
                .await
            {
                Ok(rendezvous) => rendezvous,
                Err(error) => {
                    report_pair_readiness(&mut readiness_tx, Err(error.to_string()));
                    return Err(error);
                }
            };
            let discovery = tokio::select! {
                result = rendezvous.wait_for_initial_discovery(&mut shutdown, readiness_deadline) => result,
                _ = device_stop.changed() => Err(anyhow::anyhow!("companion device listener stopped before discovery readiness")),
            };
            if let Err(error) = discovery {
                let message = error.to_string();
                let teardown = rendezvous.shutdown_checked().await;
                report_pair_readiness(&mut readiness_tx, Err(message));
                teardown.context("active companion listener readiness teardown")?;
                return Err(error);
            }
            report_pair_readiness(&mut readiness_tx, Ok(()));
            let serving_deadline = tokio::time::Instant::now() + Duration::from_secs(24 * 60 * 60);
            let connection = tokio::select! {
                biased;
                _ = shutdown.changed() => None,
                _ = device_stop.changed() => None,
                _ = tokio::time::sleep_until(serving_deadline) => None,
                value = rendezvous.recv() => value,
            };
            let Some(mut connection) = connection else {
                rendezvous.shutdown_checked().await?;
                break;
            };
            // Native Noise admission has already pinned this remote key.  The
            // authority repeats the durable device binding before challenge.
            if connection.is_initiator {
                drop(connection);
                rendezvous.shutdown_checked().await?;
                continue;
            }
            if grant.scope == CompanionScope::ChatSend {
                self.run_chat_connection(
                    &grant,
                    connection,
                    rendezvous,
                    shutdown.clone(),
                    device_stop.clone(),
                )
                .await?;
                continue;
            }
            let remote_key = *connection.remote_public_key();
            let nonce = match random_32() {
                Ok(value) => value,
                Err(error) => {
                    drop(connection);
                    rendezvous.shutdown_checked().await?;
                    return Err(error);
                }
            };
            let challenge = match self.authority.begin_reconnect_for_observed_noise(
                remote_key,
                self.listener_generation,
                self.daemon_boot_id.clone(),
                nonce,
                companion_now_unix_i64()?,
            ) {
                Ok(value) if value.device_id == grant.device_id => value,
                Ok(_) => {
                    drop(connection);
                    rendezvous.shutdown_checked().await?;
                    anyhow::bail!("listener/grant mapping drift");
                }
                Err(error) => {
                    let denied = match CompanionDenied::new(CompanionDeniedCode::DeviceDenied) {
                        Ok(value) => ServerFrame::Denied(value),
                        Err(frame_error) => {
                            drop(connection);
                            rendezvous.shutdown_checked().await?;
                            return Err(frame_error.into());
                        }
                    };
                    if let Err(denial_error) = write_frame(&mut connection, &denied).await {
                        drop(connection);
                        rendezvous.shutdown_checked().await?;
                        tracing::warn!(%denial_error, "companion reconnect denial was not delivered");
                        return Err(denial_error
                            .context("reconnect denied and denial frame was unverified"));
                    }
                    drop(connection);
                    rendezvous.shutdown_checked().await?;
                    tracing::debug!(%error, "companion v3 reconnect refused");
                    continue;
                }
            };
            if let Err(error) =
                write_frame(&mut connection, &ServerFrame::StatusChallenge(challenge)).await
            {
                drop(connection);
                rendezvous.shutdown_checked().await?;
                tracing::debug!(%error, "companion v3 status challenge write failed");
                continue;
            }
            let proof: StatusProof = match read_frame(&mut connection).await {
                Ok(value) => value,
                Err(error) => {
                    drop(connection);
                    rendezvous.shutdown_checked().await?;
                    tracing::debug!(%error, "companion v3 status proof read failed");
                    continue;
                }
            };
            let lease = match self
                .authority
                .authorize_status(&proof, companion_now_unix_i64()?)
            {
                Ok(value) => value,
                Err(error) => {
                    let denied = match CompanionDenied::new(CompanionDeniedCode::DeviceDenied) {
                        Ok(value) => ServerFrame::Denied(value),
                        Err(frame_error) => {
                            drop(connection);
                            rendezvous.shutdown_checked().await?;
                            return Err(frame_error.into());
                        }
                    };
                    if let Err(denial_error) = write_frame(&mut connection, &denied).await {
                        drop(connection);
                        rendezvous.shutdown_checked().await?;
                        tracing::warn!(%denial_error, "companion status denial was not delivered");
                        return Err(denial_error
                            .context("status proof denied and denial frame was unverified"));
                    }
                    drop(connection);
                    rendezvous.shutdown_checked().await?;
                    tracing::debug!(%error, "companion v3 status proof denied");
                    continue;
                }
            };
            let snapshot = self.redacted_snapshot(proof.device_id.clone()).await?;
            // Ownership moves out of the listener. We immediately join it; the
            // status write and carrier drain can never become orphaned.
            let delivery = StatusDelivery::spawn(
                lease,
                snapshot,
                connection,
                rendezvous,
                shutdown.clone(),
                Arc::clone(&self.readiness),
            );
            let terminal = delivery.join().await?;
            tracing::debug!(?terminal, "companion v3 status delivery terminal");
            // The rendezvous was one-shot and checked by StatusDelivery. A
            // later reconnect rebuilds a bounded listener with this grant.
        }
        Ok(())
    }

    async fn run_chat_connection(
        &self,
        grant: &DeviceGrant,
        mut connection: peeroxide::SwarmConnection,
        rendezvous: crate::cluster::hyperswarm::SharedPublicRendezvous,
        shutdown: watch::Receiver<bool>,
        device_stop: watch::Receiver<bool>,
    ) -> Result<()> {
        // Every pre-lease error still owns an accepted carrier. Finish its
        // checked teardown before classifying an unauthenticated disconnect or
        // denial as routine; a failed teardown remains an observable runtime
        // error and leaves the listener owner non-terminal.
        let challenge = match random_32().and_then(|nonce| {
            self.authority.begin_chat_reconnect_for_observed_noise(
                *connection.remote_public_key(),
                self.listener_generation,
                self.daemon_boot_id.clone(),
                nonce,
                companion_now_unix_i64()?,
            )
        }) {
            Ok(value) if value.device_id == grant.device_id => value,
            Ok(_) => {
                return self
                    .close_unaccepted_chat_connection(
                        connection,
                        rendezvous,
                        anyhow::anyhow!("chat listener/grant mapping drift"),
                    )
                    .await;
            }
            Err(error) => {
                return self
                    .close_unaccepted_chat_connection(connection, rendezvous, error)
                    .await;
            }
        };
        if let Err(error) =
            write_frame(&mut connection, &ServerFrame::ChatChallenge(challenge)).await
        {
            return self
                .close_unaccepted_chat_connection(connection, rendezvous, error)
                .await;
        }
        let request: CompanionChatRequest = match read_frame(&mut connection).await {
            Ok(value) => value,
            Err(error) => {
                return self
                    .close_unaccepted_chat_connection(connection, rendezvous, error)
                    .await;
            }
        };
        let request_id = request.request_id;
        let now = match companion_now_unix_i64() {
            Ok(value) => value,
            Err(error) => {
                return self
                    .close_unaccepted_chat_connection(connection, rendezvous, error)
                    .await;
            }
        };
        let lease = match self.authority.authorize_chat(&request, now) {
            Ok(value) => value,
            Err(error) => {
                // This denial is best-effort public feedback only. A peer
                // disconnect while receiving it is expected, but its local
                // carrier still must finish a checked teardown.
                let denial_result = match CompanionDenied::new(CompanionDeniedCode::DeviceDenied) {
                    Ok(denied) => write_frame(&mut connection, &ServerFrame::Denied(denied)).await,
                    Err(frame_error) => Err(frame_error.into()),
                };
                let reason = match denial_result {
                    Ok(()) => error,
                    Err(denial_error) => {
                        error.context(format!("chat denial write failed: {denial_error}"))
                    }
                };
                return self
                    .close_unaccepted_chat_connection(connection, rendezvous, reason)
                    .await;
            }
        };
        let effect_gate = lease.chat_effect_gate();
        let daemon_request = crate::daemon::audit_rpc::DaemonPlainChatRequest {
            schema_version: crate::daemon::audit_rpc::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
            message: request.message,
        };
        let cancellation = crate::cli::chat_turn_pipeline::ChatTurnCancellation::default();
        let cancelled_by_owner = Arc::new(AtomicBool::new(false));
        let cancelled_by_owner_task = Arc::clone(&cancelled_by_owner);
        let owner_cancel = tokio::spawn(cancel_chat_on_owner_stop(
            cancellation.clone(),
            shutdown.clone(),
            device_stop,
            cancelled_by_owner_task,
        ));
        let result = self
            .chat_runtime
            .execute_companion_chat_turn(daemon_request, cancellation.clone(), effect_gate)
            .await;
        cancellation.close();
        if let Err(error) = owner_cancel
            .await
            .context("companion chat cancellation owner panicked")
        {
            drop(connection);
            let teardown = rendezvous.shutdown_checked().await;
            self.mark_degraded().await;
            return match teardown {
                Ok(()) => Err(error.context("chat cancellation owner was not terminal")),
                Err(teardown_error) => Err(error.context(format!(
                    "chat cancellation owner and carrier teardown were unproven: {teardown_error}"
                ))),
            };
        }
        let terminal = if cancelled_by_owner.load(Ordering::Acquire) {
            // The provider may have crossed a concrete effect boundary before
            // its cancellation was observed. Do not label that response as
            // accepted or claim a remote abort.
            CompanionChatTerminal {
                schema_version: COMPANION_V3_SCHEMA_VERSION,
                request_id,
                outcome: CompanionChatOutcome::Indeterminate,
                records: Vec::new(),
                provider: None,
                model: None,
            }
        } else {
            match result {
                Ok(response) => CompanionChatTerminal {
                    schema_version: COMPANION_V3_SCHEMA_VERSION,
                    request_id,
                    outcome: CompanionChatOutcome::Accepted,
                    records: response
                        .records
                        .into_iter()
                        .map(|record| CompanionChatRecord {
                            kind: match record.kind {
                                crate::daemon::audit_rpc::DaemonPlainChatRecordKind::Stdout => {
                                    CompanionChatRecordKind::Stdout
                                }
                                crate::daemon::audit_rpc::DaemonPlainChatRecordKind::Stderr => {
                                    CompanionChatRecordKind::Stderr
                                }
                                crate::daemon::audit_rpc::DaemonPlainChatRecordKind::Notice => {
                                    CompanionChatRecordKind::Notice
                                }
                            },
                            text: record.text,
                        })
                        .collect(),
                    provider: Some(response.terminal.provider),
                    model: Some(response.terminal.model),
                },
                Err(error) => CompanionChatTerminal {
                    schema_version: COMPANION_V3_SCHEMA_VERSION,
                    request_id,
                    outcome: match error {
                        CompanionChatTurnError::Denied => CompanionChatOutcome::Denied,
                        CompanionChatTurnError::Busy => CompanionChatOutcome::Busy,
                        CompanionChatTurnError::Unavailable => CompanionChatOutcome::Unavailable,
                        CompanionChatTurnError::Timeout => CompanionChatOutcome::Timeout,
                        CompanionChatTurnError::Indeterminate => {
                            CompanionChatOutcome::Indeterminate
                        }
                    },
                    records: Vec::new(),
                    provider: None,
                    model: None,
                },
            }
        };
        let bytes = match lease.chat_terminal_frame(terminal) {
            Ok(bytes) => bytes,
            // A bounded daemon response can still exceed the mobile carrier's
            // terminal cap after envelope overhead. Do not truncate or call it
            // accepted: replace it before any write with a fresh public
            // indeterminate terminal for this exact request id.
            Err(_) => match lease.chat_terminal_frame(CompanionChatTerminal {
                schema_version: COMPANION_V3_SCHEMA_VERSION,
                request_id,
                outcome: CompanionChatOutcome::Indeterminate,
                records: Vec::new(),
                provider: None,
                model: None,
            }) {
                Ok(bytes) => bytes,
                Err(error) => {
                    // No carrier write began. A checked drain permits the
                    // marker to close; an unproven drain deliberately leaves
                    // it behind for reload recovery.
                    drop(connection);
                    match rendezvous.shutdown_checked().await {
                        Ok(()) => {
                            lease.complete_confirmed().context(
                                "close no-write companion chat marker after terminal serialization failure",
                            )?;
                            return Err(error.into());
                        }
                        Err(teardown_error) => {
                            self.mark_degraded().await;
                            return Err(anyhow::anyhow!(
                                "companion chat terminal serialization and carrier drain failed: {error}; {teardown_error}"
                            ));
                        }
                    }
                }
            },
        };
        let write = connection.write(&bytes).await;
        drop(connection);
        let drained = rendezvous.shutdown_checked().await;
        match (write, drained) {
            (Ok(()), Ok(())) => {
                lease.complete_confirmed()?;
                Ok(())
            }
            (Err(write_error), Ok(())) => {
                // The write completed with a local failure and the actor has
                // drained. This proves no later local terminal write exists;
                // it does not claim a remote retract or observation.
                lease.complete_confirmed()?;
                tracing::debug!(%write_error, "companion chat terminal write failed after local carrier terminal");
                Ok(())
            }
            (_, Err(teardown_error)) => {
                self.mark_degraded().await;
                anyhow::bail!(
                    "companion chat terminal carrier drain is indeterminate: {teardown_error}"
                )
            }
        }
    }

    async fn close_unaccepted_chat_connection(
        &self,
        connection: peeroxide::SwarmConnection,
        rendezvous: crate::cluster::hyperswarm::SharedPublicRendezvous,
        reason: anyhow::Error,
    ) -> Result<()> {
        drop(connection);
        match rendezvous.shutdown_checked().await {
            Ok(()) => {
                tracing::debug!(%reason, "companion chat connection ended before a lease");
                Ok(())
            }
            Err(teardown) => {
                self.mark_degraded().await;
                Err(reason.context(format!(
                    "unaccepted companion chat connection could not prove carrier teardown: {teardown}"
                )))
            }
        }
    }

    async fn redacted_snapshot(
        &self,
        device_id: CompanionDeviceId,
    ) -> Result<CompanionStatusSnapshot> {
        // There is no fabricated counter.  This vertical exposes only daemon
        // lifecycle readiness and deliberately leaves unknown turn metadata out.
        Ok(CompanionStatusSnapshot {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id,
            daemon_boot_id: self.daemon_boot_id.clone(),
            readiness: *self.readiness.read().await,
            observed_at_unix: companion_now_unix_i64()?,
            // This daemon vertical has no owned turn-inventory observer yet.
            // `None` is intentionally different from a measured empty list.
            active_turns: None,
        })
    }

    async fn enroll_after_verified_pairing(
        self: &Arc<Self>,
        proof: EnrollmentProof,
        observed_invite_noise: [u8; 32],
        topic: [u8; 32],
        requested_scope: CompanionScope,
        diagnostics: &mut CompanionPairDiagnostics,
    ) -> Result<EnrollmentAccepted> {
        diagnostics.phase("enrollment_begin");
        anyhow::ensure!(
            proof.requested_scope == requested_scope,
            "pairing scope differs from daemon invite"
        );
        let reconnect = ReconnectDescriptor {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            carrier: "peeroxide-hyperswarm-v3".into(),
            rendezvous_topic: topic,
            daemon_noise_public_key: self.daemon_key.public_key,
            descriptor_generation: self.listener_generation,
        };
        let pending = self.authority.begin_enrollment(
            proof,
            observed_invite_noise,
            reconnect.clone(),
            companion_now_unix_i64()?,
        )?;
        diagnostics.phase("enrollment_authority_pending");
        self.complete_pending_audit(pending.clone()).await?;
        diagnostics.phase("enrollment_audit_finalized");
        let grant = self.authority.device(&pending.device_id)?;
        if let Err(readiness_error) = self.spawn_active_listener(grant).await {
            diagnostics.phase("active_listener_unready");
            // The enrollment receipt is already durable, so an unready active
            // descriptor must be withdrawn through the existing durable revoke
            // path before this caller can observe an accepted pairing result.
            match self.revoke_device(pending.device_id).await {
                Ok(true) => diagnostics.phase("enrollment_rollback_proven"),
                Ok(false) => diagnostics.phase("enrollment_rollback_noop"),
                Err(revoke_error) => {
                    diagnostics.phase("enrollment_rollback_unproven");
                    self.mark_degraded().await;
                    return Err(revoke_error).context(format!(
                        "companion active listener readiness failed and durable rollback was not proven: {readiness_error:#}"
                    ));
                }
            }
            return Err(readiness_error)
                .context("companion active listener was not ready before enrollment acceptance");
        }
        diagnostics.phase("active_listener_ready");
        Ok(EnrollmentAccepted {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: pending.device_id,
            revision: pending.revision,
            granted_scope: requested_scope,
            reconnect,
        })
    }
}

fn load_or_create_server_key(home: &Path) -> Result<peeroxide::KeyPair> {
    std::fs::create_dir_all(home).context("create NEOTH home for companion v3 key")?;
    let _lock = crate::util::locked_file::lock_file_blocking(
        &home.join(SERVER_KEY_LOCK),
        "companion v3 server key",
    )?;
    let path = home.join(SERVER_KEY_FILE);
    let record = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<ServerKeyRecord>(&bytes)
            .context("parse companion v3 server key")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).context("mint companion v3 server key")?;
            let record = ServerKeyRecord {
                schema_version: COMPANION_V3_SCHEMA_VERSION,
                seed,
            };
            crate::util::atomic_write::atomic_write_private(&path, &serde_json::to_vec(&record)?)
                .context("persist companion v3 server key before QR publication")?;
            record
        }
        Err(error) => return Err(error).context("read companion v3 server key"),
    };
    anyhow::ensure!(
        record.schema_version == COMPANION_V3_SCHEMA_VERSION
            && record.seed.iter().any(|byte| *byte != 0),
        "invalid companion v3 server key"
    );
    Ok(peeroxide::KeyPair::from_seed(record.seed))
}

fn device_view(grant: DeviceGrant) -> Result<CompanionV3DeviceView> {
    let grant_state = grant.phase_name().to_owned();
    Ok(CompanionV3DeviceView {
        device_id: grant.device_id,
        label: grant.label,
        revision: grant.revision,
        grant_state,
    })
}

fn companion_now_unix_i64() -> Result<i64> {
    i64::try_from(crate::time::now_unix_secs())
        .context("companion v3 wall clock exceeds signed protocol range")
}

fn signal_listener_stop(owner: &DeviceListenerOwner, operation: &'static str) -> Result<()> {
    match owner.stop_tx.send(true) {
        Ok(()) => Ok(()),
        // The receiver can already be gone only when the owned task has
        // reached a terminal path. Its JoinHandle remains the required proof;
        // a missing handle is never accepted as a successful drain.
        Err(_) if owner.task.is_some() => {
            tracing::debug!(
                operation,
                "companion listener stop receiver was already closed; joining retained task"
            );
            Ok(())
        }
        Err(_) => anyhow::bail!(
            "{operation} could not signal companion listener and no join handle remains"
        ),
    }
}

async fn join_companion_task(
    task: tokio::task::JoinHandle<Result<()>>,
    label: &'static str,
) -> Result<()> {
    task.await
        .with_context(|| format!("{label} task panicked or was cancelled"))?
        .with_context(|| format!("{label} task returned an unverified terminal error"))
}
const COMPANION_DIAGNOSTICS_ENV: &str = "NEOTH_COMPANION_DIAGNOSTICS";

/// One listener emits each fixed phase at most once. The bitset bounds output
/// under hostile repeated connections and never carries peer material.
struct CompanionPairDiagnostics {
    enabled: bool,
    emitted: u32,
    last_phase: &'static str,
}

impl CompanionPairDiagnostics {
    fn from_environment() -> Self {
        Self {
            enabled: std::env::var(COMPANION_DIAGNOSTICS_ENV).as_deref() == Ok("1"),
            emitted: 0,
            last_phase: "bootstrap_started",
        }
    }

    fn phase(&mut self, phase: &'static str) {
        let bit = match phase {
            "bootstrap_started" => 0,
            "bootstrap_ready" => 1,
            "topic_joined" => 2,
            "awaiting_connection" => 3,
            "connection_received" => 4,
            "psk_verified" => 5,
            "proof_read" => 6,
            "response_written" => 7,
            "teardown_started" => 8,
            "teardown_completed" => 9,
            "enrollment_begin" => 10,
            "enrollment_authority_pending" => 11,
            "enrollment_audit_finalized" => 12,
            "active_listener_ready" => 13,
            "active_listener_unready" => 14,
            "enrollment_rollback_proven" => 15,
            "enrollment_rollback_noop" => 16,
            "enrollment_rollback_unproven" => 17,
            "pair_rendezvous_leave_started" => 18,
            "pair_rendezvous_left" => 19,
            "enrollment_response_write_started" => 20,
            "teardown_failed" => 21,
            "rendezvous_started" => 22,
            "initial_discovery_started" => 23,
            _ => return,
        };
        self.last_phase = phase;
        if self.enabled && self.emitted & (1 << bit) == 0 {
            self.emitted |= 1 << bit;
            eprintln!("NEOTH_COMPANION_PAIR_PHASE={phase}");
        }
    }

    fn failed(&mut self, last: &'static str) {
        if self.enabled {
            eprintln!("NEOTH_COMPANION_PAIR_PHASE=failed.{last}");
        }
    }

    fn last_phase(&self) -> &'static str {
        self.last_phase
    }
}

fn random_32() -> Result<[u8; 32]> {
    let mut value = [0u8; 32];
    getrandom::getrandom(&mut value)?;
    Ok(value)
}
fn listener_stop_requested(
    daemon_shutdown: &watch::Receiver<bool>,
    device_stop: &watch::Receiver<bool>,
) -> bool {
    *daemon_shutdown.borrow() || *device_stop.borrow()
}

/// This future owns no provider work. It only converts a daemon or per-device
/// listener stop into the existing turn cancellation, and the caller always
/// joins it before selecting a public terminal.
async fn cancel_chat_on_owner_stop(
    cancellation: crate::cli::chat_turn_pipeline::ChatTurnCancellation,
    mut daemon_stop: watch::Receiver<bool>,
    mut device_stop: watch::Receiver<bool>,
    stopped_by_owner: Arc<AtomicBool>,
) {
    if *daemon_stop.borrow() || *device_stop.borrow() {
        stopped_by_owner.store(true, Ordering::Release);
        cancellation.close();
        return;
    }
    tokio::select! {
        changed = daemon_stop.changed() => {
            let _ = changed;
            stopped_by_owner.store(true, Ordering::Release);
        }
        changed = device_stop.changed() => {
            let _ = changed;
            stopped_by_owner.store(true, Ordering::Release);
        }
        _ = cancellation.cancelled() => {}
    }
    cancellation.close();
}
fn invite_client_noise_key(topic: &[u8; 32], psk: &[u8; 16]) -> [u8; 32] {
    // The invite bootstrap remains exactly v2: topic is HKDF salt, one-time
    // PSK is IKM, and this derives only the ephemeral pre-auth transport key.
    // It is deliberately distinct from the durable device reconnect key.
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(topic), psk);
    let mut seed = [0u8; 32];
    hkdf.expand(b"NEOTH/companion/noise-static/v2", &mut seed)
        .expect("fixed 32-byte HKDF expansion");
    peeroxide::KeyPair::from_seed(seed).public_key
}
fn constant_time_eq(actual: &[u8], expected: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn remaining_pair_invite_ttl(deadline: tokio::time::Instant) -> Result<u64> {
    remaining_pair_invite_ttl_at(deadline, tokio::time::Instant::now())
}

fn remaining_pair_invite_ttl_at(
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Result<u64> {
    let remaining = deadline
        .checked_duration_since(now)
        .context("companion invite expired before readiness")?;
    let whole_seconds = remaining.as_secs();
    anyhow::ensure!(
        (1..=INVITE_TTL_SECS).contains(&whole_seconds),
        "companion invite has no publishable remaining TTL after readiness"
    );
    Ok(whole_seconds)
}
fn request_runtime_shutdown(shutdown_tx: &watch::Sender<bool>) {
    // `send()` without a live receiver does not persist a value for a later
    // subscription. Pair tasks subscribe inside their spawned future, so use
    // the watch value itself as the durable shutdown state.
    shutdown_tx.send_replace(true);
}

fn build_pair_url(
    topic: [u8; 32],
    psk: [u8; 16],
    server_pk: [u8; 32],
    ttl: u64,
    scope: CompanionScope,
) -> String {
    format!(
        "neoth://companion/pair?v=3&topic={}&psk={}&server_pk={}&ttl={}&scope={}",
        hex::encode(topic),
        hex::encode(psk),
        hex::encode(server_pk),
        ttl,
        scope.as_str(),
    )
}
async fn write_frame(
    connection: &mut peeroxide::SwarmConnection,
    frame: &ServerFrame,
) -> Result<()> {
    let bytes = crate::daemon::companion_protocol::encode_server_frame(frame)?;
    tokio::time::timeout(CONNECTION_FRAME_TIMEOUT, connection.write(&bytes))
        .await
        .context("companion v3 frame write timeout")??;
    Ok(())
}
async fn read_frame<T: for<'a> Deserialize<'a>>(
    connection: &mut peeroxide::SwarmConnection,
) -> Result<T> {
    let bytes = tokio::time::timeout(CONNECTION_FRAME_TIMEOUT, connection.read())
        .await
        .context("companion v3 frame read timeout")??
        .context("companion v3 frame closed")?;
    Ok(crate::daemon::companion_protocol::decode_frame(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_pair_qr_binds_exact_persistent_server_noise_key_before_invite_publication() {
        let home = tempfile::tempdir().unwrap();
        let key = load_or_create_server_key(home.path()).unwrap();
        let url = build_pair_url(
            [1; 32],
            [2; 16],
            key.public_key,
            INVITE_TTL_SECS,
            CompanionScope::StatusRead,
        );
        assert_eq!(
            url,
            format!(
                "neoth://companion/pair?v=3&topic={}&psk={}&server_pk={}&ttl={}&scope={}",
                "01".repeat(32),
                "02".repeat(16),
                hex::encode(key.public_key),
                INVITE_TTL_SECS,
                CompanionScope::StatusRead.as_str(),
            )
        );
        assert!(
            !url.contains("seed"),
            "the private responder seed never enters the QR"
        );
    }

    #[test]
    fn v3_restart_reloads_the_same_private_server_key() {
        let home = tempfile::tempdir().unwrap();
        let first = load_or_create_server_key(home.path()).unwrap().public_key;
        let second = load_or_create_server_key(home.path()).unwrap().public_key;
        assert_eq!(
            first, second,
            "restart must retain the key pinned by paired clients"
        );
    }

    #[tokio::test]
    async fn runtime_shutdown_before_pair_listener_subscription_exits_cleanly() {
        let home = tempfile::tempdir().expect("create companion stop-race home");
        let config_path = home.path().join("freedom.yaml");
        let config = crate::config::FreedomConfig::default();
        let crate::cli::serve_tasks::WalSetup {
            segment_path,
            writer,
            writer_join,
            ..
        } = crate::cli::serve_tasks::prepare_wal(home.path(), None)
            .await
            .expect("prepare companion stop-race WAL");
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path.clone(),
        ));
        let chat = Arc::new(DaemonChatRuntime::new(
            home.path().to_path_buf(),
            config_path,
            segment_path,
            controller,
            writer.clone(),
        ));
        let runtime = CompanionRuntime::load(
            home.path().to_path_buf(),
            writer.clone(),
            Arc::clone(&chat),
            "testboot".into(),
            1,
        )
        .expect("load companion runtime");

        request_runtime_shutdown(&runtime.shutdown_tx);
        tokio::time::timeout(
            Duration::from_secs(1),
            runtime.run_pair_listener([1; 32], [2; 16], CompanionScope::StatusRead),
        )
        .await
        .expect("stopped pair listener returns without rendezvous")
        .expect("persistent stop is a clean listener terminal");

        drop(runtime);
        drop(chat);
        drop(writer);
        tokio::time::timeout(Duration::from_secs(5), writer_join)
            .await
            .expect("companion stop-race writer drains within bound")
            .expect("join companion stop-race writer")
            .expect("companion stop-race writer succeeds");
    }

    #[tokio::test]
    async fn audit_rpc_refusal_requires_retained_pair_owner_join() {
        let home = tempfile::tempdir().expect("create companion refusal home");
        let config_path = home.path().join("freedom.yaml");
        let crate::cli::serve_tasks::WalSetup {
            segment_path,
            writer,
            writer_join,
            ..
        } = crate::cli::serve_tasks::prepare_wal(home.path(), None)
            .await
            .expect("prepare companion refusal WAL");
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            config_path.clone(),
        ));
        let chat = Arc::new(DaemonChatRuntime::new(
            home.path().to_path_buf(),
            config_path,
            segment_path,
            controller,
            writer.clone(),
        ));
        let runtime = CompanionRuntime::load(
            home.path().to_path_buf(),
            writer.clone(),
            Arc::clone(&chat),
            "testboot".into(),
            1,
        )
        .expect("load companion runtime");

        let (stop_tx, _stop_rx) = watch::channel(false);
        runtime.pair_tasks.lock().await.insert(
            "refused".to_owned(),
            PairListenerOwner {
                stop_tx,
                task: tokio::spawn(async { Ok::<(), anyhow::Error>(()) }),
            },
        );
        runtime
            .join_proven_refused_pair_listener("refused")
            .await
            .expect("an observed listener terminal is joined before audit-RPC refusal");
        assert!(
            runtime.pair_tasks.lock().await.is_empty(),
            "settled refusal leaves no listener owner for shutdown"
        );
        assert!(
            runtime
                .join_proven_refused_pair_listener("refused")
                .await
                .is_err(),
            "missing ownership is uncertain and must not become a recoverable refusal"
        );

        drop(runtime);
        drop(chat);
        drop(writer);
        tokio::time::timeout(Duration::from_secs(5), writer_join)
            .await
            .expect("companion refusal writer drains within bound")
            .expect("join companion refusal writer")
            .expect("companion refusal writer succeeds");
    }

    #[tokio::test]
    async fn companion_v3_shutdown_drains_all_owners_after_first_listener_error_before_writer_join()
    {
        let home = tempfile::tempdir().expect("create companion drain home");
        let config_path = home.path().join("freedom.yaml");
        let crate::cli::serve_tasks::WalSetup {
            segment_path,
            writer,
            writer_join,
            ..
        } = crate::cli::serve_tasks::prepare_wal(home.path(), None)
            .await
            .expect("prepare companion drain WAL");
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            config_path.clone(),
        ));
        let chat = Arc::new(DaemonChatRuntime::new(
            home.path().to_path_buf(),
            config_path,
            segment_path,
            controller,
            writer.clone(),
        ));
        let runtime = CompanionRuntime::load(
            home.path().to_path_buf(),
            writer.clone(),
            Arc::clone(&chat),
            "testboot".into(),
            1,
        )
        .expect("load companion runtime");

        let (pair_stop_tx, _pair_stop_rx) = watch::channel(false);
        runtime.pair_tasks.lock().await.insert(
            "first-failure".to_owned(),
            PairListenerOwner {
                stop_tx: pair_stop_tx,
                task: tokio::spawn(async {
                    anyhow::bail!("simulated first pair listener failure")
                }),
            },
        );
        let (device_stop_tx, mut device_stop_rx) = watch::channel(false);
        let retained_writer = writer.clone();
        let later_owner_joined = Arc::new(AtomicBool::new(false));
        let later_owner_joined_task = Arc::clone(&later_owner_joined);
        runtime.listener_tasks.lock().await.insert(
            Uuid::nil(),
            DeviceListenerOwner {
                stop_tx: device_stop_tx,
                task: Some(tokio::spawn(async move {
                    device_stop_rx.changed().await.expect("owner stop signal");
                    drop(retained_writer);
                    later_owner_joined_task.store(true, Ordering::Release);
                    Ok(())
                })),
            },
        );

        assert!(
            runtime.shutdown_and_drain().await.is_err(),
            "first listener error remains visible"
        );
        assert!(runtime.pair_tasks.lock().await.is_empty());
        assert!(runtime.listener_tasks.lock().await.is_empty());
        assert!(
            later_owner_joined.load(Ordering::Acquire),
            "later owner reached its successful terminal after the stop signal"
        );
        drop(runtime);
        drop(chat);
        drop(writer);
        tokio::time::timeout(Duration::from_secs(5), writer_join)
            .await
            .expect("later owner released its retained WAL sender")
            .expect("join companion drain writer")
            .expect("companion drain writer succeeds");
    }

    #[tokio::test]
    async fn per_device_stop_prevents_new_reconnect_acceptance_without_global_shutdown() {
        let (_daemon_tx, daemon_rx) = watch::channel(false);
        let (device_tx, device_rx) = watch::channel(false);
        assert!(!listener_stop_requested(&daemon_rx, &device_rx));
        device_tx.send(true).unwrap();
        assert!(listener_stop_requested(&daemon_rx, &device_rx));
    }

    #[tokio::test]
    async fn accepted_chat_owner_cancels_on_per_device_stop_before_terminal_selection() {
        let (_daemon_tx, daemon_rx) = watch::channel(false);
        let (device_tx, device_rx) = watch::channel(false);
        let cancellation = crate::cli::chat_turn_pipeline::ChatTurnCancellation::default();
        let owner_stop = Arc::new(AtomicBool::new(false));
        let waiter = tokio::spawn(cancel_chat_on_owner_stop(
            cancellation.clone(),
            daemon_rx,
            device_rx,
            Arc::clone(&owner_stop),
        ));
        device_tx.send(true).unwrap();
        waiter.await.unwrap();
        assert!(owner_stop.load(Ordering::Acquire));
        assert!(cancellation.is_closed());
    }

    #[test]
    fn cancelled_before_write_closes_only_after_checked_carrier_drain() {
        assert!(local_carrier_terminal(
            LocalDeliveryState::NoWriteStarted,
            true,
        ));
        assert!(!local_carrier_terminal(
            LocalDeliveryState::NoWriteStarted,
            false,
        ));
    }

    #[tokio::test]
    async fn listener_join_failure_is_not_converted_into_a_successful_drain() {
        let task = tokio::spawn(async { anyhow::bail!("simulated listener terminal failure") });
        assert!(join_companion_task(task, "test listener").await.is_err());
    }

    #[tokio::test]
    async fn closed_listener_stop_requires_the_retained_task_terminal_proof() {
        let (stop_tx, stop_rx) = watch::channel(false);
        drop(stop_rx);
        let owner = DeviceListenerOwner {
            stop_tx,
            task: Some(tokio::spawn(async { Ok(()) })),
        };
        assert!(signal_listener_stop(&owner, "test drain").is_ok());
        assert!(
            join_companion_task(owner.task.unwrap(), "test drain")
                .await
                .is_ok()
        );

        let (orphan_stop_tx, orphan_stop_rx) = watch::channel(false);
        drop(orphan_stop_rx);
        let orphan = DeviceListenerOwner {
            stop_tx: orphan_stop_tx,
            task: None,
        };
        assert!(signal_listener_stop(&orphan, "test drain").is_err());
    }

    #[tokio::test]
    async fn pair_listener_owner_cancellation_signals_before_join() {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let owner = PairListenerOwner {
            stop_tx,
            task: tokio::spawn(async move {
                stop_rx
                    .changed()
                    .await
                    .expect("pair owner stop sender remains live");
                assert!(*stop_rx.borrow());
                Ok(())
            }),
        };
        owner.stop_tx.send_replace(true);
        assert!(
            join_companion_task(owner.task, "pair listener owner cancellation")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn pair_readiness_defers_publication_until_initial_discovery_completes() {
        let (mut ready_tx, _ready_rx) = oneshot::channel::<PairListenerReadiness>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let mut waiter = tokio::spawn(async move {
            wait_for_pair_readiness_or_caller_drop(
                async move {
                    release_rx.await.expect("release initial discovery barrier");
                    Ok(())
                },
                &mut ready_tx,
            )
            .await
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut waiter)
                .await
                .is_err(),
            "pair publication readiness must remain pending before initial discovery completes"
        );
        release_tx.send(()).expect("release test discovery barrier");
        assert!(matches!(
            waiter.await.expect("join readiness waiter"),
            PairReadinessWait::Discovery(Ok(()))
        ));
    }

    #[tokio::test]
    async fn pair_readiness_caller_cancellation_is_observed_before_publication() {
        let (mut ready_tx, ready_rx) = oneshot::channel::<PairListenerReadiness>();
        drop(ready_rx);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_pair_readiness_or_caller_drop(std::future::pending(), &mut ready_tx),
        )
        .await
        .expect("closed caller is observed without waiting for discovery");
        assert!(matches!(result, PairReadinessWait::CallerCancelled));
    }

    #[test]
    fn pair_invite_ttl_is_remaining_and_never_reset_after_readiness() {
        let now = tokio::time::Instant::now();
        assert_eq!(
            remaining_pair_invite_ttl_at(now + Duration::from_millis(1_500), now).unwrap(),
            1
        );
        assert_eq!(
            remaining_pair_invite_ttl_at(now + Duration::from_secs(INVITE_TTL_SECS), now).unwrap(),
            INVITE_TTL_SECS
        );
        assert!(remaining_pair_invite_ttl_at(now + Duration::from_millis(500), now).is_err());
        assert!(remaining_pair_invite_ttl_at(now, now).is_err());
    }
    // Cross-module delivery/revocation regression belongs with the R4
    // authority fixture: it must prove PendingRevoke is visible before it
    // waits, the in-flight owner retains its lease through shutdown_checked(),
    // and the stable WAL mutation id resumes after restart. This candidate
    // deliberately does not duplicate the protocol/authority fixture or claim
    // it executed under the local BSOD hold.
}
