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
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock, watch};
use uuid::Uuid;

use crate::{
    daemon::{
        companion_authority::{
            AuditObservation, DeviceAuthority, DeviceGrant, MutationKind, PendingAudit, Reconcile,
            StatusLease,
        },
        companion_protocol::{
            COMPANION_V3_SCHEMA_VERSION, CompanionDenied, CompanionDeniedCode, CompanionDeviceId,
            CompanionReadiness, CompanionStatusSnapshot, EnrollmentAccepted, EnrollmentProof,
            ReconnectDescriptor, ServerFrame, StatusProof,
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
const MAX_DEVICE_LISTENERS: usize = 128;

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

impl StatusDelivery {
    fn spawn(
        lease: StatusLease,
        snapshot: CompanionStatusSnapshot,
        mut connection: peeroxide::SwarmConnection,
        rendezvous: crate::cluster::hyperswarm::PublicRendezvous,
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
    writer: WalWriterHandle,
    daemon_key: peeroxide::KeyPair,
    daemon_boot_id: String,
    listener_generation: u64,
    readiness: Arc<RwLock<CompanionReadiness>>,
    shutdown_tx: watch::Sender<bool>,
    pair_tasks: Arc<Mutex<BTreeMap<String, tokio::task::JoinHandle<Result<()>>>>>,
    listener_tasks: Arc<Mutex<BTreeMap<Uuid, DeviceListenerOwner>>>,
}

impl CompanionRuntime {
    /// Constructing this runtime first reads/creates the private server seed.
    /// Therefore every QR emitted by this daemon contains the public key that
    /// the subsequent Peeroxide responder actually uses.
    pub(crate) fn load(
        home: PathBuf,
        writer: WalWriterHandle,
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
            writer,
            daemon_key,
            daemon_boot_id,
            listener_generation,
            readiness: Arc::new(RwLock::new(CompanionReadiness::Starting)),
            shutdown_tx,
            pair_tasks: Arc::new(Mutex::new(BTreeMap::new())),
            listener_tasks: Arc::new(Mutex::new(BTreeMap::new())),
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
        // A closed watch channel means every listener has already released its
        // receiver.  That is a classified no-live-owner condition; the joins
        // below still prove every retained task terminal before WAL shutdown.
        if self.shutdown_tx.send(true).is_err() {
            tracing::debug!("companion runtime shutdown had no live receivers");
        }
        // Take ownership before joining; no mutex is held across a listener
        // await, so every carrier can observe cancellation and drain before
        // the final WAL sender is released.
        let pairs = std::mem::take(&mut *self.pair_tasks.lock().await);
        let mut first_error = None;
        for (_, task) in pairs {
            if let Err(error) = join_companion_task(task, "pair listener").await {
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
        if let Some(error) = first_error {
            self.mark_degraded().await;
            return Err(error);
        }
        Ok(())
    }

    /// Only called by the authenticated daemon IPC handler.  It creates a
    /// fresh one-time v3 topic/PSK, but it never starts a transient responder:
    /// the daemon's persistent key has already been loaded above.
    pub(crate) async fn mint_pair_invite(self: &Arc<Self>) -> Result<CompanionV3Invite> {
        let mut topic = [0u8; 32];
        let mut psk = [0u8; 16];
        getrandom::getrandom(&mut topic).context("mint companion v3 topic")?;
        getrandom::getrandom(&mut psk).context("mint companion v3 psk")?;
        self.spawn_pair_listener(topic, psk).await?;
        let url = build_pair_url(topic, psk, self.daemon_key.public_key, INVITE_TTL_SECS);
        Ok(CompanionV3Invite {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            pair_url: url,
            expires_in_secs: INVITE_TTL_SECS,
        })
    }

    async fn spawn_pair_listener(self: &Arc<Self>, topic: [u8; 32], psk: [u8; 16]) -> Result<()> {
        self.reap_finished_pair_tasks().await?;
        let key = hex::encode(topic);
        let mut tasks = self.pair_tasks.lock().await;
        anyhow::ensure!(
            tasks.len() < MAX_DEVICE_LISTENERS,
            "companion pairing listener cap reached"
        );
        anyhow::ensure!(
            !tasks.contains_key(&key),
            "duplicate companion pairing topic"
        );
        let runtime = Arc::clone(self);
        let task = tokio::spawn(async move { runtime.run_pair_listener(topic, psk).await });
        tasks.insert(key, task);
        Ok(())
    }

    async fn run_pair_listener(self: &Arc<Self>, topic: [u8; 32], psk: [u8; 16]) -> Result<()> {
        let expected_client_noise = invite_client_noise_key(&topic, &psk);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(INVITE_TTL_SECS);
        let mut shutdown = self.shutdown_tx.subscribe();
        let mut rendezvous = crate::cluster::hyperswarm::spawn_public_rendezvous_with_key(
            topic,
            expected_client_noise,
            self.daemon_key.clone(),
            deadline,
            shutdown.clone(),
        )
        .await?;
        let result = async {
            loop {
                let next = tokio::select! {
                    biased;
                    _ = shutdown.changed() => None,
                    _ = tokio::time::sleep_until(deadline) => None,
                    next = rendezvous.recv() => next,
                };
                let Some(mut connection) = next else { break; };
                if connection.is_initiator { continue; }
                let observed_noise = *connection.remote_public_key();
                let raw_psk = tokio::time::timeout(CONNECTION_FRAME_TIMEOUT, connection.read()).await
                    .context("v3 pair psk read timeout")??.context("v3 pair closed before psk")?;
                if !constant_time_eq(&raw_psk, &psk) { continue; }
                let proof: EnrollmentProof = read_frame(&mut connection).await?;
                let accepted = match self.enroll_after_verified_pairing(proof, observed_noise, topic).await {
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
                rendezvous.leave().await?;
                write_frame(&mut connection, &ServerFrame::EnrollmentAccepted(accepted)).await?;
                break;
            }
            Ok(())
        }.await;
        let teardown = rendezvous.shutdown_checked().await;
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
        // Refuse obvious invalid phase transitions before stopping the owned
        // listener. Once cancellation is signalled, the following async
        // authority call durably publishes PendingRevoke before it waits for a
        // live status lease to finish its owned carrier drain.
        let grant = self.authority.device(&device_id)?;
        if grant.phase_name() != "active" {
            return Ok(false);
        }
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
        // R6 persists PendingRevoke before waiting for an in-flight status
        // lease.  Keep the owner registered until then so a concurrent daemon
        // shutdown can still prove its terminal carrier state.
        let Some(pending) = self.authority.begin_revoke_async(&device_id).await? else {
            return Ok(false);
        };
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
        let task = tokio::spawn(async move { runtime.run_device_listener(grant, stop_rx).await });
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
        Ok(())
    }

    async fn reap_finished_pair_tasks(&self) -> Result<()> {
        let finished = {
            let mut tasks = self.pair_tasks.lock().await;
            let keys = tasks
                .iter()
                .filter_map(|(key, task)| task.is_finished().then(|| key.clone()))
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| tasks.remove(&key))
                .collect::<Vec<_>>()
        };
        for task in finished {
            if let Err(error) = join_companion_task(task, "completed pair listener").await {
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
    ) -> Result<()> {
        let topic = grant.reconnect.rendezvous_topic;
        let mut shutdown = self.shutdown_tx.subscribe();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(24 * 60 * 60);
        loop {
            if listener_stop_requested(&shutdown, &device_stop) {
                break;
            }
            let mut rendezvous = crate::cluster::hyperswarm::spawn_public_rendezvous_with_key(
                topic,
                grant.client_noise_key,
                self.daemon_key.clone(),
                deadline,
                shutdown.clone(),
            )
            .await?;
            let connection = tokio::select! {
                biased;
                _ = shutdown.changed() => None,
                _ = device_stop.changed() => None,
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

    pub(crate) async fn enroll_after_verified_pairing(
        self: &Arc<Self>,
        proof: EnrollmentProof,
        observed_invite_noise: [u8; 32],
        topic: [u8; 32],
    ) -> Result<EnrollmentAccepted> {
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
        self.complete_pending_audit(pending.clone()).await?;
        let grant = self.authority.device(&pending.device_id)?;
        self.spawn_active_listener(grant).await?;
        Ok(EnrollmentAccepted {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: pending.device_id,
            revision: pending.revision,
            granted_scope: crate::daemon::companion_protocol::CompanionScope::StatusRead,
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
fn build_pair_url(topic: [u8; 32], psk: [u8; 16], server_pk: [u8; 32], ttl: u64) -> String {
    format!(
        "neoth://companion/pair?v=3&topic={}&psk={}&server_pk={}&ttl={}",
        hex::encode(topic),
        hex::encode(psk),
        hex::encode(server_pk),
        ttl,
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
        let url = build_pair_url([1; 32], [2; 16], key.public_key, INVITE_TTL_SECS);
        assert_eq!(
            url,
            format!(
                "neoth://companion/pair?v=3&topic={}&psk={}&server_pk={}&ttl={}",
                "01".repeat(32),
                "02".repeat(16),
                hex::encode(key.public_key),
                INVITE_TTL_SECS,
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
    async fn per_device_stop_prevents_new_reconnect_acceptance_without_global_shutdown() {
        let (_daemon_tx, daemon_rx) = watch::channel(false);
        let (device_tx, device_rx) = watch::channel(false);
        assert!(!listener_stop_requested(&daemon_rx, &device_rx));
        device_tx.send(true).unwrap();
        assert!(listener_stop_requested(&daemon_rx, &device_rx));
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

    // Cross-module delivery/revocation regression belongs with the R4
    // authority fixture: it must prove PendingRevoke is visible before it
    // waits, the in-flight owner retains its lease through shutdown_checked(),
    // and the stable WAL mutation id resumes after restart. This candidate
    // deliberately does not duplicate the protocol/authority fixture or claim
    // it executed under the local BSOD hold.
}
