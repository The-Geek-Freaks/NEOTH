//! Native Rust transport boundary for the W2306 v3 companion contract.
//!
//! This is an isolated candidate.  The protocol source is deliberately shared
//! by path with W2306 rather than copied into a mobile-only codec.

#[path = "../../../SRC/neothd/src/daemon/companion_protocol.rs"]
mod companion_protocol;

use std::{
    collections::BTreeMap,
    future::Future,
    ptr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use futures_util::FutureExt;
use hkdf::Hkdf;
use peeroxide::{JoinOpts, KeyPair, SwarmConfig};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{runtime::Runtime, sync::watch, task::JoinHandle};
use uuid::Uuid;
use zeroize::Zeroize;

use companion_protocol::{
    decode_server_frame, encode_frame, ChatChallenge, CompanionChatOutcome, CompanionChatRecordKind,
    CompanionChatRequest, CompanionChatTerminal, CompanionDeniedCode, CompanionReadiness, CompanionScope,
    CompanionStatusSnapshot, EnrollmentProof, ReconnectDescriptor, ServerFrame, StatusProof,
    COMPANION_V3_SCHEMA_VERSION,
};

const SECRET_BYTES: usize = 32;
const TOPIC_BYTES: usize = 32;
const PSK_BYTES: usize = 16;
const MAX_URL_BYTES: usize = 512;
const MAX_DESCRIPTOR_BYTES: usize = 8 * 1024;
const MAX_PUBLIC_RESULT_BYTES: usize = 80 * 1024;
const MAX_LABEL_BYTES: usize = 64;
const MAX_CHAT_MESSAGE_BYTES: usize = 640;
const MAX_TTL_SECS: u64 = 300;
const CHAT_OUTER_TIMEOUT_SECS: u64 = 125;
const V2_BOOTSTRAP_INFO: &[u8] = b"NEOTH/companion/noise-static/v2";
const NOISE_DERIVATION_DOMAIN: &[u8] = b"NEOTH/companion/mobile/noise-static/v3";
const SIGNING_DERIVATION_DOMAIN: &[u8] = b"NEOTH/companion/mobile/device-signing/v3";

#[repr(C)]
pub struct neoth_companion_bridge {
    inner: Bridge,
}

#[repr(C)]
pub struct neoth_companion_operation {
    inner: Operation,
}

struct Bridge {
    runtime: Arc<Runtime>,
    device_secret: SecretBytes,
}

struct Operation {
    _runtime: Arc<Runtime>,
    cancel: watch::Sender<bool>,
    completion: Arc<(Mutex<Completion>, Condvar)>,
}

struct Completion { result: Option<PublicResult>, done: bool }

struct SecretBytes([u8; SECRET_BYTES]);

impl SecretBytes {
    fn new(value: [u8; SECRET_BYTES]) -> Self { Self(value) }
    fn copy(&self) -> Self { Self(self.0) }
}

impl Drop for SecretBytes {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PublicResult {
    Paired {
        device_id: String,
        revision: u64,
        granted_scope: &'static str,
        descriptor: PublicDescriptor,
    },
    Status {
        device_id: String,
        daemon_boot_id: String,
        readiness: String,
        observed_at_unix: i64,
        active_turns: Option<Vec<PublicTurn>>,
    },
    Denied { code: &'static str },
    Failed { code: &'static str },
    Cancelled,
    Chat(PublicChatResult),
}

#[derive(Clone, Serialize)]
struct PublicChatResult {
    kind: &'static str,
    schema_version: u8,
    request_id: String,
    outcome: &'static str,
    records: Vec<PublicChatRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
}

#[derive(Clone, Serialize)]
struct PublicChatRecord { kind: &'static str, text: String }

fn result_code(result: &PublicResult) -> i32 {
    match result {
        PublicResult::Paired { .. } | PublicResult::Status { .. } => 1,
        PublicResult::Chat(value) => match value.outcome { "accepted" => 1, "denied" => 2, _ => 3 },
        PublicResult::Denied { .. } => 2,
        PublicResult::Failed { .. } => 3,
        PublicResult::Cancelled => 4,
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicDescriptor {
    schema_version: u8,
    carrier: String,
    rendezvous_topic_hex: String,
    daemon_noise_public_key_hex: String,
    descriptor_generation: u64,
}

#[derive(Clone, Serialize)]
struct PublicTurn {
    phase: String,
    latest_sequence: u64,
}

struct PairInvite {
    topic: [u8; TOPIC_BYTES],
    psk: [u8; PSK_BYTES],
    server_key: [u8; 32],
    ttl: Duration,
    requested_scope: CompanionScope,
}

impl Bridge {
    fn new(device_secret: [u8; SECRET_BYTES]) -> Result<Self, ()> {
        let runtime = Runtime::new().map_err(|_| ())?;
        Ok(Self {
            runtime: Arc::new(runtime),
            device_secret: SecretBytes::new(device_secret),
        })
    }

    fn start_pair(&self, invite: PairInvite, label: String) -> Operation {
        let (cancel, cancel_rx) = watch::channel(false);
        let device_secret = self.device_secret.copy();
        Operation::spawn(Arc::clone(&self.runtime), cancel, async move {
            pair(device_secret, invite, label, cancel_rx).await
        })
    }

    fn start_reconnect(&self, descriptor: ReconnectDescriptor, device_id: Uuid) -> Operation {
        let (cancel, cancel_rx) = watch::channel(false);
        let device_secret = self.device_secret.copy();
        Operation::spawn(Arc::clone(&self.runtime), cancel, async move {
            reconnect(device_secret, descriptor, device_id, cancel_rx).await
        })
    }

    fn start_chat(&self, descriptor: ReconnectDescriptor, device_id: Uuid, message: String) -> Operation {
        let (cancel, cancel_rx) = watch::channel(false);
        let device_secret = self.device_secret.copy();
        Operation::spawn(Arc::clone(&self.runtime), cancel, async move {
            chat(device_secret, descriptor, device_id, message, cancel_rx).await
        })
    }
}

impl Operation {
    fn spawn(runtime: Arc<Runtime>, cancel: watch::Sender<bool>, work: impl Future<Output = PublicResult> + Send + 'static) -> Self {
        let completion = Arc::new((Mutex::new(Completion { result: None, done: false }), Condvar::new()));
        let done = Arc::clone(&completion);
        runtime.spawn(async move {
            let result = std::panic::AssertUnwindSafe(work).catch_unwind().await
                .unwrap_or(PublicResult::Failed { code: "bridge_task_panicked" });
            let (lock, wake) = &*done;
            let mut state = lock_unpoison(lock);
            state.result = Some(result);
            state.done = true;
            wake.notify_all();
        });
        Self { _runtime: runtime, cancel, completion }
    }

    fn cancel_and_drain(&self) {
        let _ = self.cancel.send(true);
        let (lock, wake) = &*self.completion;
        let mut state = lock_unpoison(lock);
        while !state.done { state = wait_unpoison(wake, state); }
    }

    fn poll(&self) -> Result<Option<PublicResult>, ()> {
        let (lock, _) = &*self.completion;
        let state = lock_unpoison(lock);
        Ok(state.done.then(|| state.result.clone()).flatten())
    }
}

async fn pair(
    device_secret: SecretBytes,
    invite: PairInvite,
    label: String,
    mut cancel: watch::Receiver<bool>,
) -> PublicResult {
    let bootstrap_key = match derive_v2_bootstrap_key(&invite.topic, &invite.psk) {
        Ok(key) => key,
        Err(()) => return PublicResult::Failed { code: "key_derivation_failed" },
    };
    let durable_noise_key = match derive_peeroxide_key(&device_secret.0) {
        Ok(key) => key,
        Err(()) => return PublicResult::Failed { code: "key_derivation_failed" },
    };
    let signing_key = match derive_signing_key(&device_secret.0) {
        Ok(key) => key,
        Err(()) => return PublicResult::Failed { code: "key_derivation_failed" },
    };
    let transport_peer_key = bootstrap_key.public_key;
    let durable_noise_public_key = durable_noise_key.public_key;
    let mut config = SwarmConfig::with_public_bootstrap();
    config.key_pair = Some(bootstrap_key);
    config.max_peers = 1;
    config.max_parallel = 1;

    let (swarm_task, swarm, mut connections) = match start_owned_swarm(config, &mut cancel, invite.ttl).await {
        Ok(value) => value,
        Err(result) => return result,
    };
    let result = pair_on_swarm(
        &swarm,
        &mut connections,
        &invite,
        &signing_key,
        transport_peer_key, durable_noise_public_key,
        &label,
        &mut cancel,
    )
    .await;
    // This is the sole owner of the swarm task. Every cancellation and every
    // terminal protocol outcome destroys then awaits the actual network task.
    let _ = swarm.destroy().await;
    let _ = swarm_task.await;
    result
}

async fn pair_on_swarm(
    swarm: &peeroxide::SwarmHandle,
    connections: &mut tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
    invite: &PairInvite,
    signing_key: &SigningKey,
    transport_peer_key: [u8; 32],
    durable_noise_public_key: [u8; 32],
    label: &str,
    cancel: &mut watch::Receiver<bool>,
) -> PublicResult {
    if swarm
        .join(invite.topic, JoinOpts { server: false, client: true })
        .await
        .is_err()
    {
        return PublicResult::Failed { code: "rendezvous_join_failed" };
    }
    let mut conn = match await_cancelable(cancel, invite.ttl, connections.recv()).await {
        Wait::Value(Some(conn)) => conn,
        Wait::Value(None) => return PublicResult::Failed { code: "transport_closed" },
        Wait::Expired => return PublicResult::Failed { code: "pair_timeout" },
        Wait::Cancelled => return PublicResult::Cancelled,
    };
    // Pin before PSK. This is deliberately an application-visible gate because
    // peeroxide exposes the authenticated remote static key only after Noise.
    if conn.remote_public_key() != &invite.server_key {
        return PublicResult::Denied { code: "daemon_key_mismatch" };
    }
    match write_cancelable(&mut conn, &invite.psk, invite.ttl, cancel).await {
        Write::Sent => {}
        Write::Cancelled => return PublicResult::Cancelled,
        Write::Expired => return PublicResult::Failed { code: "pair_timeout" },
        Write::Failed => return PublicResult::Failed { code: "transport_write_failed" },
    }

    let client_nonce = match fresh_nonce() {
        Some(value) => value,
        None => return PublicResult::Failed { code: "entropy_unavailable" },
    };
    let enrollment = match EnrollmentProof::signed(
        invite.topic,
        transport_peer_key,
        durable_noise_public_key,
        client_nonce,
        invite.requested_scope.clone(),
        label.to_owned(),
        signing_key,
    ) {
        Ok(value) => value,
        Err(_) => return PublicResult::Failed { code: "enrollment_encode_failed" },
    };
    let encoded = match encode_frame(&enrollment) {
        Ok(value) => value,
        Err(_) => return PublicResult::Failed { code: "enrollment_encode_failed" },
    };
    match write_cancelable(&mut conn, &encoded, invite.ttl, cancel).await {
        Write::Sent => {}
        Write::Cancelled => return PublicResult::Cancelled,
        Write::Expired => return PublicResult::Failed { code: "pair_timeout" },
        Write::Failed => return PublicResult::Failed { code: "transport_write_failed" },
    }
    let accepted = match await_cancelable(cancel, invite.ttl, conn.read()).await {
        Wait::Value(Ok(Some(frame))) => match decode_server_frame(&frame) {
            Ok(ServerFrame::EnrollmentAccepted(value)) => value,
            Ok(ServerFrame::Denied(value)) => return public_denied(value.code),
            Ok(_) | Err(_) => return PublicResult::Denied { code: "enrollment_rejected" },
        },
        Wait::Value(Ok(None)) => return PublicResult::Failed { code: "transport_closed" },
        Wait::Value(Err(_)) => return PublicResult::Failed { code: "transport_read_failed" },
        Wait::Expired => return PublicResult::Failed { code: "pair_timeout" },
        Wait::Cancelled => return PublicResult::Cancelled,
    };
    if accepted.schema_version != COMPANION_V3_SCHEMA_VERSION
        || accepted.granted_scope != invite.requested_scope
        || accepted.reconnect.validate().is_err()
        || accepted.reconnect.daemon_noise_public_key != invite.server_key
    {
        return PublicResult::Denied { code: "invalid_reconnect_descriptor" };
    }
    PublicResult::Paired {
        device_id: accepted.device_id.to_string(),
        revision: accepted.revision,
        granted_scope: accepted.granted_scope.as_str(),
        descriptor: public_descriptor(&accepted.reconnect),
    }
}

async fn reconnect(
    device_secret: SecretBytes,
    descriptor: ReconnectDescriptor,
    expected_device_id: Uuid,
    mut cancel: watch::Receiver<bool>,
) -> PublicResult {
    if descriptor.validate().is_err() {
        return PublicResult::Failed { code: "invalid_reconnect_descriptor" };
    }
    let noise_key = match derive_peeroxide_key(&device_secret.0) {
        Ok(key) => key,
        Err(()) => return PublicResult::Failed { code: "key_derivation_failed" },
    };
    let signing_key = match derive_signing_key(&device_secret.0) {
        Ok(key) => key,
        Err(()) => return PublicResult::Failed { code: "key_derivation_failed" },
    };
    let mut config = SwarmConfig::with_public_bootstrap();
    config.key_pair = Some(noise_key);
    config.max_peers = 1;
    config.max_parallel = 1;
    let (swarm_task, swarm, mut connections) = match start_owned_swarm(config, &mut cancel, Duration::from_secs(MAX_TTL_SECS)).await {
        Ok(value) => value,
        Err(result) => return result,
    };
    let result = reconnect_on_swarm(
        &swarm,
        &mut connections,
        &descriptor,
        expected_device_id,
        &signing_key,
        &mut cancel,
    )
    .await;
    let _ = swarm.destroy().await;
    let _ = swarm_task.await;
    result
}

async fn reconnect_on_swarm(
    swarm: &peeroxide::SwarmHandle,
    connections: &mut tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
    descriptor: &ReconnectDescriptor,
    expected_device_id: Uuid,
    signing_key: &SigningKey,
    cancel: &mut watch::Receiver<bool>,
) -> PublicResult {
    if swarm
        .join(descriptor.rendezvous_topic, JoinOpts { server: false, client: true })
        .await
        .is_err()
    {
        return PublicResult::Failed { code: "rendezvous_join_failed" };
    }
    let timeout = Duration::from_secs(MAX_TTL_SECS);
    let mut conn = match await_cancelable(cancel, timeout, connections.recv()).await {
        Wait::Value(Some(conn)) => conn,
        Wait::Value(None) => return PublicResult::Failed { code: "transport_closed" },
        Wait::Expired => return PublicResult::Failed { code: "reconnect_timeout" },
        Wait::Cancelled => return PublicResult::Cancelled,
    };
    if conn.remote_public_key() != &descriptor.daemon_noise_public_key {
        return PublicResult::Denied { code: "daemon_key_mismatch" };
    }
    let challenge = match await_cancelable(cancel, timeout, conn.read()).await {
        Wait::Value(Ok(Some(frame))) => match decode_server_frame(&frame) {
            Ok(ServerFrame::StatusChallenge(value)) => value,
            Ok(ServerFrame::Denied(value)) => return public_denied(value.code),
            Ok(_) | Err(_) => return PublicResult::Failed { code: "invalid_server_frame" },
        },
        Wait::Value(Ok(None)) => return PublicResult::Failed { code: "transport_closed" },
        Wait::Value(Err(_)) => return PublicResult::Failed { code: "transport_read_failed" },
        Wait::Expired => return PublicResult::Failed { code: "reconnect_timeout" },
        Wait::Cancelled => return PublicResult::Cancelled,
    };
    if challenge.device_id.0 != expected_device_id || challenge.validate().is_err() {
        return PublicResult::Denied { code: "invalid_status_challenge" };
    }
    let proof = match StatusProof::signed(&challenge, signing_key).and_then(|proof| {
        encode_frame(&proof).map(|frame| (proof, frame))
    }) {
        Ok((_proof, frame)) => frame,
        Err(_) => return PublicResult::Failed { code: "status_proof_failed" },
    };
    match write_cancelable(&mut conn, &proof, timeout, cancel).await {
        Write::Sent => {}
        Write::Cancelled => return PublicResult::Cancelled,
        Write::Expired => return PublicResult::Failed { code: "reconnect_timeout" },
        Write::Failed => return PublicResult::Failed { code: "transport_write_failed" },
    }
    match await_cancelable(cancel, timeout, conn.read()).await {
        Wait::Value(Ok(Some(frame))) => match decode_server_frame(&frame) {
            Ok(ServerFrame::StatusSnapshot(value)) => public_status(value, expected_device_id),
            Ok(ServerFrame::Denied(value)) => public_denied(value.code),
            Ok(_) | Err(_) => PublicResult::Failed { code: "invalid_server_frame" },
        },
        Wait::Value(Ok(None)) => PublicResult::Failed { code: "transport_closed" },
        Wait::Value(Err(_)) => PublicResult::Failed { code: "transport_read_failed" },
        Wait::Expired => PublicResult::Failed { code: "reconnect_timeout" },
        Wait::Cancelled => PublicResult::Cancelled,
    }
}

async fn chat(
    device_secret: SecretBytes,
    descriptor: ReconnectDescriptor,
    expected_device_id: Uuid,
    message: String,
    mut cancel: watch::Receiver<bool>,
) -> PublicResult {
    if descriptor.validate().is_err() { return PublicResult::Failed { code: "invalid_reconnect_descriptor" }; }
    let noise_key = match derive_peeroxide_key(&device_secret.0) { Ok(key) => key, Err(()) => return PublicResult::Failed { code: "key_derivation_failed" } };
    let signing_key = match derive_signing_key(&device_secret.0) { Ok(key) => key, Err(()) => return PublicResult::Failed { code: "key_derivation_failed" } };
    let mut config = SwarmConfig::with_public_bootstrap(); config.key_pair = Some(noise_key); config.max_peers = 1; config.max_parallel = 1;
    let (swarm_task, swarm, mut connections) = match start_owned_swarm(config, &mut cancel, Duration::from_secs(CHAT_OUTER_TIMEOUT_SECS)).await { Ok(value) => value, Err(result) => return result };
    let result = chat_on_swarm(&swarm, &mut connections, &descriptor, expected_device_id, message, &signing_key, &mut cancel).await;
    // Cancellation must not detach a rendezvous worker. Destroy the carrier
    // and await the sole worker before publishing this terminal result.
    let _ = swarm.destroy().await;
    let _ = swarm_task.await;
    result
}

async fn chat_on_swarm(
    swarm: &peeroxide::SwarmHandle,
    connections: &mut tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
    descriptor: &ReconnectDescriptor,
    expected_device_id: Uuid,
    message: String,
    signing_key: &SigningKey,
    cancel: &mut watch::Receiver<bool>,
) -> PublicResult {
    let timeout = Duration::from_secs(CHAT_OUTER_TIMEOUT_SECS);
    if swarm.join(descriptor.rendezvous_topic, JoinOpts { server: false, client: true }).await.is_err() { return PublicResult::Failed { code: "transport_join_failed" }; }
    let mut conn = match await_cancelable(cancel, timeout, connections.recv()).await { Wait::Value(Some(value)) => value, Wait::Value(None) => return PublicResult::Failed { code: "transport_closed" }, Wait::Expired => return PublicResult::Failed { code: "chat_connect_timeout" }, Wait::Cancelled => return PublicResult::Cancelled };
    if conn.remote_public_key() != &descriptor.daemon_noise_public_key { return PublicResult::Denied { code: "daemon_key_mismatch" }; }
    let challenge = match await_cancelable(cancel, timeout, conn.read()).await {
        Wait::Value(Ok(Some(frame))) => match decode_server_frame(&frame) { Ok(ServerFrame::ChatChallenge(value)) => value, Ok(ServerFrame::Denied(value)) => return public_denied(value.code), Ok(_) | Err(_) => return PublicResult::Failed { code: "invalid_server_frame" } },
        Wait::Value(Ok(None)) => return PublicResult::Failed { code: "transport_closed" }, Wait::Value(Err(_)) => return PublicResult::Failed { code: "transport_read_failed" }, Wait::Expired => return PublicResult::Failed { code: "chat_challenge_timeout" }, Wait::Cancelled => return PublicResult::Cancelled,
    };
    if challenge.device_id.0 != expected_device_id || challenge.validate().is_err() { return PublicResult::Denied { code: "invalid_chat_challenge" }; }
    let request_id = Uuid::now_v7();
    let request = match CompanionChatRequest::signed(&challenge, request_id, message, signing_key) { Ok(value) => value, Err(_) => return PublicResult::Failed { code: "invalid_chat_request" } };
    let bytes = match encode_frame(&request) { Ok(value) => value, Err(_) => return PublicResult::Failed { code: "invalid_chat_request" } };
    if *cancel.borrow() { return PublicResult::Cancelled; }
    match write_cancelable(&mut conn, &bytes, timeout, cancel).await {
        Write::Sent => {}
        Write::Cancelled | Write::Expired | Write::Failed => return public_indeterminate(request_id),
    }
    match await_cancelable(cancel, timeout, conn.read()).await {
        Wait::Value(Ok(Some(frame))) => match decode_server_frame(&frame) {
            Ok(ServerFrame::ChatTerminal(value)) => public_chat_terminal(value, request_id),
            Ok(ServerFrame::Denied(value)) => public_denied(value.code),
            Ok(_) | Err(_) => public_indeterminate(request_id),
        },
        Wait::Value(Ok(None)) | Wait::Value(Err(_)) | Wait::Expired | Wait::Cancelled => public_indeterminate(request_id),
    }
}

enum Wait<T> { Value(T), Expired, Cancelled }
enum Write { Sent, Failed, Expired, Cancelled }

async fn start_owned_swarm(
    config: SwarmConfig,
    cancel: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> Result<
    (
        JoinHandle<()>,
        peeroxide::SwarmHandle,
        tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
    ),
    PublicResult,
> {
    let startup = peeroxide::spawn_starting(config)
        .await
        .map_err(|_| PublicResult::Failed { code: "transport_start_failed" })?;
    match await_cancelable(cancel, timeout, startup.bootstrapped()).await {
        Wait::Value(Ok(())) => startup
            .finish()
            .await
            .map_err(|_| PublicResult::Failed { code: "transport_start_failed" }),
        Wait::Value(Err(_)) => {
            let _ = startup.shutdown().await;
            Err(PublicResult::Failed { code: "transport_start_failed" })
        }
        Wait::Expired => {
            let _ = startup.shutdown().await;
            Err(PublicResult::Failed { code: "transport_start_timeout" })
        }
        Wait::Cancelled => {
            let _ = startup.shutdown().await;
            Err(PublicResult::Cancelled)
        }
    }
}

async fn await_cancelable<T>(
    cancel: &mut watch::Receiver<bool>,
    timeout: Duration,
    future: impl Future<Output = T>,
) -> Wait<T> {
    if *cancel.borrow() {
        return Wait::Cancelled;
    }
    tokio::select! {
        biased;
        _changed = cancel.changed() => Wait::Cancelled,
        _ = tokio::time::sleep(timeout) => Wait::Expired,
        value = future => Wait::Value(value),
    }
}

async fn write_cancelable(
    conn: &mut peeroxide::SwarmConnection,
    bytes: &[u8],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
) -> Write {
    match await_cancelable(cancel, timeout, conn.write(bytes)).await {
        Wait::Value(Ok(())) => Write::Sent,
        Wait::Value(Err(_)) => Write::Failed,
        Wait::Expired => Write::Expired,
        Wait::Cancelled => Write::Cancelled,
    }
}

fn public_denied(code: CompanionDeniedCode) -> PublicResult {
    let code = match code {
        CompanionDeniedCode::DeviceDenied => "device_denied",
        CompanionDeniedCode::InvalidFrame => "invalid_frame",
        CompanionDeniedCode::RetryLater => "retry_later",
        CompanionDeniedCode::Unavailable => "unavailable",
    };
    PublicResult::Denied { code }
}

fn public_indeterminate(request_id: Uuid) -> PublicResult {
    PublicResult::Chat(PublicChatResult { kind: "chat", schema_version: COMPANION_V3_SCHEMA_VERSION, request_id: request_id.to_string(), outcome: "indeterminate", records: Vec::new(), provider: None, model: None })
}

fn public_chat_terminal(terminal: CompanionChatTerminal, expected_request_id: Uuid) -> PublicResult {
    if terminal.validate().is_err() || terminal.request_id != expected_request_id { return public_indeterminate(expected_request_id); }
    let outcome = match terminal.outcome { CompanionChatOutcome::Accepted => "accepted", CompanionChatOutcome::Denied => "denied", CompanionChatOutcome::Busy => "busy", CompanionChatOutcome::Unavailable => "unavailable", CompanionChatOutcome::Timeout => "timeout", CompanionChatOutcome::Indeterminate => "indeterminate" };
    let records = terminal.records.into_iter().map(|record| PublicChatRecord { kind: match record.kind { CompanionChatRecordKind::Stdout => "stdout", CompanionChatRecordKind::Stderr => "stderr", CompanionChatRecordKind::Notice => "notice" }, text: record.text }).collect();
    PublicResult::Chat(PublicChatResult { kind: "chat", schema_version: terminal.schema_version, request_id: terminal.request_id.to_string(), outcome, records, provider: terminal.provider, model: terminal.model })
}

fn public_status(snapshot: CompanionStatusSnapshot, expected_device_id: Uuid) -> PublicResult {
    if snapshot.validate().is_err() || snapshot.device_id.0 != expected_device_id {
        return PublicResult::Denied { code: "invalid_status_snapshot" };
    }
    let readiness = match snapshot.readiness {
        CompanionReadiness::Ready => "ready",
        CompanionReadiness::Starting => "starting",
        CompanionReadiness::Degraded => "degraded",
        CompanionReadiness::Unavailable => "unavailable",
    };
    PublicResult::Status {
        device_id: snapshot.device_id.to_string(),
        daemon_boot_id: snapshot.daemon_boot_id,
        readiness: readiness.to_owned(),
        observed_at_unix: snapshot.observed_at_unix,
        active_turns: snapshot.active_turns.map(|turns| turns.into_iter().map(|turn| PublicTurn {
            phase: turn.phase,
            latest_sequence: turn.latest_sequence,
        }).collect()),
    }
}

fn derive_peeroxide_key(secret: &[u8; SECRET_BYTES]) -> Result<KeyPair, ()> {
    let mut seed = [0u8; 32];
    Hkdf::<Sha256>::new(Some(NOISE_DERIVATION_DOMAIN), secret)
        .expand(b"peeroxide-static", &mut seed)
        .map_err(|_| ())?;
    let result = KeyPair::from_seed(seed);
    zeroize_bytes(&mut seed);
    Ok(result)
}

/// This is byte-for-byte the existing daemon's pre-auth v2 admission key:
/// HKDF-SHA256(salt=topic, IKM=PSK, info=NEOTH/companion/noise-static/v2).
/// It is invite-specific and must never be reused as the durable v3 identity.
fn derive_v2_bootstrap_key(topic: &[u8; TOPIC_BYTES], psk: &[u8; PSK_BYTES]) -> Result<KeyPair, ()> {
    let mut seed = [0u8; 32];
    Hkdf::<Sha256>::new(Some(topic), psk)
        .expand(V2_BOOTSTRAP_INFO, &mut seed)
        .map_err(|_| ())?;
    let result = KeyPair::from_seed(seed);
    zeroize_bytes(&mut seed);
    Ok(result)
}

fn derive_signing_key(secret: &[u8; SECRET_BYTES]) -> Result<SigningKey, ()> {
    let mut seed = [0u8; 32];
    Hkdf::<Sha256>::new(Some(SIGNING_DERIVATION_DOMAIN), secret)
        .expand(b"ed25519-signing", &mut seed)
        .map_err(|_| ())?;
    let result = SigningKey::from_bytes(&seed);
    zeroize_bytes(&mut seed);
    Ok(result)
}

fn fresh_nonce() -> Option<[u8; 32]> {
    // The actual mobile build must retain the existing `getrandom` dependency;
    // it is intentionally not made a caller-provided FFI input.
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).ok()?;
    Some(nonce)
}

fn public_descriptor(descriptor: &ReconnectDescriptor) -> PublicDescriptor {
    PublicDescriptor {
        schema_version: descriptor.schema_version,
        carrier: descriptor.carrier.clone(),
        rendezvous_topic_hex: hex::encode(descriptor.rendezvous_topic),
        daemon_noise_public_key_hex: hex::encode(descriptor.daemon_noise_public_key),
        descriptor_generation: descriptor.descriptor_generation,
    }
}

fn decode_public_descriptor(bytes: &[u8]) -> Result<ReconnectDescriptor, ()> {
    if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES { return Err(()); }
    let public = serde_json::from_slice::<PublicDescriptor>(bytes).map_err(|_| ())?;
    let descriptor = ReconnectDescriptor {
        schema_version: public.schema_version,
        carrier: public.carrier,
        rendezvous_topic: lower_hex_array(&public.rendezvous_topic_hex, TOPIC_BYTES)?,
        daemon_noise_public_key: lower_hex_array(&public.daemon_noise_public_key_hex, 32)?,
        descriptor_generation: public.descriptor_generation,
    };
    descriptor.validate().map_err(|_| ())?;
    Ok(descriptor)
}

fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() { Ok(value) => value, Err(error) => error.into_inner() }
}

fn wait_unpoison<'a, T>(condvar: &Condvar, guard: std::sync::MutexGuard<'a, T>) -> std::sync::MutexGuard<'a, T> {
    match condvar.wait(guard) { Ok(value) => value, Err(error) => error.into_inner() }
}

fn parse_invite(bytes: &[u8]) -> Result<PairInvite, ()> {
    if bytes.is_empty() || bytes.len() > MAX_URL_BYTES {
        return Err(());
    }
    let value = std::str::from_utf8(bytes).map_err(|_| ())?;
    let query = value.strip_prefix("neoth://companion/pair?").ok_or(())?;
    let mut fields = BTreeMap::new();
    for item in query.split('&') {
        let (key, value) = item.split_once('=').ok_or(())?;
        if fields.insert(key, value).is_some() { return Err(()); }
    }
    if !(fields.len() == 5 || fields.len() == 6) || fields.get("v") != Some(&"3") { return Err(()); }
    let requested_scope = match fields.get("scope") { None => CompanionScope::StatusRead, Some(&"companion.status.read") => CompanionScope::StatusRead, Some(&"companion.chat.send") => CompanionScope::ChatSend, _ => return Err(()) };
    let ttl: u64 = fields.get("ttl").ok_or(())?.parse().map_err(|_| ())?;
    if !(1..=MAX_TTL_SECS).contains(&ttl) { return Err(()); }
    Ok(PairInvite {
        topic: lower_hex_array(fields.get("topic").ok_or(())?, TOPIC_BYTES)?,
        psk: lower_hex_array(fields.get("psk").ok_or(())?, PSK_BYTES)?,
        server_key: lower_hex_array(fields.get("server_pk").ok_or(())?, 32)?,
        ttl: Duration::from_secs(ttl),
        requested_scope,
    })
}

fn lower_hex_array<const N: usize>(value: &str, expected: usize) -> Result<[u8; N], ()> {
    if value.len() != expected * 2 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(());
    }
    let mut output = [0u8; N];
    hex::decode_to_slice(value, &mut output).map_err(|_| ())?;
    Ok(output)
}

fn label_from(bytes: &[u8]) -> Result<String, ()> {
    let value = std::str::from_utf8(bytes).map_err(|_| ())?;
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(value.to_owned())
}

fn chat_message_from(bytes: &[u8]) -> Result<String, ()> {
    let value = std::str::from_utf8(bytes).map_err(|_| ())?;
    if value.is_empty() || value.len() > MAX_CHAT_MESSAGE_BYTES || value.trim_start().starts_with('/') { return Err(()); }
    Ok(value.to_owned())
}

fn encode_public_result(result: &PublicResult) -> Result<Vec<u8>, ()> {
    match result { PublicResult::Chat(value) => serde_json::to_vec(value).map_err(|_| ()), _ => serde_json::to_vec(result).map_err(|_| ()) }
}

unsafe fn borrowed<'a, T>(value: *mut T) -> Option<&'a T> { unsafe { value.as_ref() } }
unsafe fn owned<T>(value: *mut T) -> Option<Box<T>> {
    if value.is_null() { None } else { Some(unsafe { Box::from_raw(value) }) }
}
unsafe fn input<'a>(value: *const u8, len: usize, max: usize) -> Option<&'a [u8]> {
    if value.is_null() || len == 0 || len > max { None } else { Some(unsafe { std::slice::from_raw_parts(value, len) }) }
}

fn ffi_ptr<T>(work: impl FnOnce() -> *mut T) -> *mut T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or(ptr::null_mut())
}
fn ffi_code(work: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or(-1)
}
fn ffi_void(work: impl FnOnce()) { let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)); }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_bridge_new(
    device_secret: *const u8,
    device_secret_len: usize,
) -> *mut neoth_companion_bridge { ffi_ptr(|| unsafe {
    let Some(bytes) = input(device_secret, device_secret_len, SECRET_BYTES) else { return ptr::null_mut() };
    if bytes.len() != SECRET_BYTES { return ptr::null_mut(); }
    let mut secret = [0u8; SECRET_BYTES];
    secret.copy_from_slice(bytes);
    match Bridge::new(secret) {
        Ok(inner) => Box::into_raw(Box::new(neoth_companion_bridge { inner })),
        Err(()) => ptr::null_mut(),
    }
}) }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_bridge_free(bridge: *mut neoth_companion_bridge) { ffi_void(|| unsafe { let _ = owned(bridge); }); }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_pair_start(
    bridge: *mut neoth_companion_bridge,
    pair_url: *const u8,
    pair_url_len: usize,
    label: *const u8,
    label_len: usize,
) -> *mut neoth_companion_operation { ffi_ptr(|| unsafe {
    let Some(bridge) = borrowed(bridge) else { return ptr::null_mut() };
    let Some(pair_url) = input(pair_url, pair_url_len, MAX_URL_BYTES) else { return ptr::null_mut() };
    let Some(label) = input(label, label_len, MAX_LABEL_BYTES) else { return ptr::null_mut() };
    let Ok(invite) = parse_invite(pair_url) else { return ptr::null_mut() };
    let Ok(label) = label_from(label) else { return ptr::null_mut() };
    Box::into_raw(Box::new(neoth_companion_operation { inner: bridge.inner.start_pair(invite, label) }))
}) }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_reconnect_start(
    bridge: *mut neoth_companion_bridge,
    descriptor_json: *const u8,
    descriptor_json_len: usize,
    device_id: *const u8,
    device_id_len: usize,
) -> *mut neoth_companion_operation { ffi_ptr(|| unsafe {
    let Some(bridge) = borrowed(bridge) else { return ptr::null_mut() };
    let Some(descriptor_json) = input(descriptor_json, descriptor_json_len, MAX_DESCRIPTOR_BYTES) else { return ptr::null_mut() };
    let Some(device_id) = input(device_id, device_id_len, 36) else { return ptr::null_mut() };
    // No malformed public descriptor may turn into an alternate auth path.
    let Ok(descriptor) = decode_public_descriptor(descriptor_json) else { return ptr::null_mut() };
    let Some(device_id) = std::str::from_utf8(device_id).ok().and_then(|id| Uuid::parse_str(id).ok()) else { return ptr::null_mut() };
    if descriptor.validate().is_err() { return ptr::null_mut(); }
    Box::into_raw(Box::new(neoth_companion_operation { inner: bridge.inner.start_reconnect(descriptor, device_id) }))
}) }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_chat_start(
    bridge: *mut neoth_companion_bridge,
    descriptor_json: *const u8,
    descriptor_json_len: usize,
    device_id: *const u8,
    device_id_len: usize,
    message: *const u8,
    message_len: usize,
) -> *mut neoth_companion_operation { ffi_ptr(|| unsafe {
    let Some(bridge) = borrowed(bridge) else { return ptr::null_mut() };
    let Some(descriptor_json) = input(descriptor_json, descriptor_json_len, MAX_DESCRIPTOR_BYTES) else { return ptr::null_mut() };
    let Some(device_id) = input(device_id, device_id_len, 36) else { return ptr::null_mut() };
    let Some(message) = input(message, message_len, MAX_CHAT_MESSAGE_BYTES) else { return ptr::null_mut() };
    let Ok(descriptor) = decode_public_descriptor(descriptor_json) else { return ptr::null_mut() };
    let Some(device_id) = std::str::from_utf8(device_id).ok().and_then(|id| Uuid::parse_str(id).ok()) else { return ptr::null_mut() };
    let Ok(message) = chat_message_from(message) else { return ptr::null_mut() };
    Box::into_raw(Box::new(neoth_companion_operation { inner: bridge.inner.start_chat(descriptor, device_id, message) }))
}) }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_operation_poll(
    operation: *mut neoth_companion_operation,
    out: *mut u8,
    out_len: usize,
    required_len: *mut usize,
) -> i32 { ffi_code(|| unsafe {
    let Some(operation) = borrowed(operation) else { return -1 };
    let result = match operation.inner.poll() { Ok(value) => value, Err(()) => return -1 };
    let Some(result) = result else { return 0 };
    let encoded = match encode_public_result(&result) { Ok(value) if value.len() <= MAX_PUBLIC_RESULT_BYTES => value, _ => return -1 };
    if !required_len.is_null() { *required_len = encoded.len(); }
    if out.is_null() || out_len < encoded.len() { return 5; }
    ptr::copy_nonoverlapping(encoded.as_ptr(), out, encoded.len());
    result_code(&result)
}) }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_operation_cancel(operation: *mut neoth_companion_operation) { ffi_void(|| unsafe { if let Some(operation) = borrowed(operation) { operation.inner.cancel_and_drain(); } }); }

#[unsafe(no_mangle)]
pub extern "C" fn neoth_companion_operation_free(operation: *mut neoth_companion_operation) { ffi_void(|| unsafe { if let Some(operation) = owned(operation) { operation.inner.cancel_and_drain(); } }); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_v3_invite_is_exact_and_lowercase() {
        let invite = parse_invite(b"neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=300").unwrap();
        assert_eq!(invite.topic, [0xaa; 32]);
        assert_eq!(invite.psk, [0xbb; 16]);
        assert_eq!(invite.server_key, [0xcc; 32]);
    }

    #[test]
    fn invite_rejects_unknown_duplicate_or_unpinned_values() {
        assert!(parse_invite(b"neoth://companion/pair?v=3&topic=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=30").is_err());
        assert!(parse_invite(b"neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&ttl=30").is_err());
    }

    #[test]
    fn old_invite_defaults_to_status_scope_and_chat_scope_is_explicit() {
        let old = parse_invite(b"neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=30").unwrap();
        assert!(matches!(old.requested_scope, CompanionScope::StatusRead));
        let chat = parse_invite(b"neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=30&scope=companion.chat.send").unwrap();
        assert!(matches!(chat.requested_scope, CompanionScope::ChatSend));
        assert!(parse_invite(b"neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=30&scope=chat-send").is_err());
    }

    #[test]
    fn chat_message_rejects_actions_and_preserves_ordinary_utf8() {
        assert!(chat_message_from(b"  /restart").is_err());
        assert!(chat_message_from(&vec![b'x'; MAX_CHAT_MESSAGE_BYTES + 1]).is_err());
        assert_eq!(chat_message_from("Hallo 🙂".as_bytes()).unwrap(), "Hallo 🙂");
    }

    #[test]
    fn device_secret_domains_produce_separate_deterministic_keys() {
        let secret = [7u8; 32];
        let noise = derive_peeroxide_key(&secret).unwrap().public_key;
        let signing = derive_signing_key(&secret).unwrap().verifying_key().to_bytes();
        assert_ne!(noise, signing);
        assert_eq!(noise, derive_peeroxide_key(&secret).unwrap().public_key);
    }

    #[test]
    fn v2_bootstrap_key_is_invite_bound_and_distinct_from_durable_v3_key() {
        let topic = [0x11; TOPIC_BYTES];
        let psk = [0x22; PSK_BYTES];
        let mut daemon_seed = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&topic), &psk)
            .expand(b"NEOTH/companion/noise-static/v2", &mut daemon_seed)
            .unwrap();
        let daemon_equivalent = KeyPair::from_seed(daemon_seed).public_key;
        let bridge = derive_v2_bootstrap_key(&topic, &psk).unwrap().public_key;
        let durable = derive_peeroxide_key(&[0x33; SECRET_BYTES]).unwrap().public_key;
        assert_eq!(bridge, daemon_equivalent, "must satisfy existing daemon pre-auth admission");
        assert_ne!(bridge, durable, "invite transport key must not become durable reconnect identity");
    }

    #[test]
    fn exact_public_descriptor_round_trips_to_reconnect_descriptor() {
        let source = ReconnectDescriptor {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            carrier: "peeroxide-hyperswarm-v3".to_owned(),
            rendezvous_topic: [0x44; 32],
            daemon_noise_public_key: [0x55; 32],
            descriptor_generation: 9,
        };
        let encoded = serde_json::to_vec(&public_descriptor(&source)).unwrap();
        assert_eq!(decode_public_descriptor(&encoded).unwrap(), source);
        assert!(decode_public_descriptor(br#"{"schema_version":3,"carrier":"peeroxide-hyperswarm-v3","rendezvous_topic_hex":"4444444444444444444444444444444444444444444444444444444444444444","daemon_noise_public_key_hex":"5555555555555555555555555555555555555555555555555555555555555555","descriptor_generation":9,"extra":true}"#).is_err());
    }

    #[test]
    fn absent_active_turn_inventory_stays_absent_in_public_status() {
        let id = Uuid::nil();
        let result = public_status(CompanionStatusSnapshot {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: companion_protocol::CompanionDeviceId(id),
            daemon_boot_id: "boot".to_owned(), readiness: CompanionReadiness::Ready,
            observed_at_unix: 1, active_turns: None,
        }, id);
        assert!(matches!(result, PublicResult::Status { active_turns: None, .. }));
    }

    #[test]
    fn public_results_keep_the_flat_ffi_shape_and_stable_scope_text() {
        let descriptor = PublicDescriptor {
            schema_version: 3,
            carrier: "peeroxide-hyperswarm-v3".to_owned(),
            rendezvous_topic_hex: "44".repeat(32),
            daemon_noise_public_key_hex: "55".repeat(32),
            descriptor_generation: 9,
        };
        let paired = serde_json::to_value(PublicResult::Paired {
            device_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            revision: 7,
            granted_scope: CompanionScope::ChatSend.as_str(),
            descriptor,
        }).unwrap();
        assert_eq!(paired, serde_json::json!({
            "state": "paired",
            "device_id": "00000000-0000-0000-0000-000000000001",
            "revision": 7,
            "granted_scope": "companion.chat.send",
            "descriptor": {
                "schema_version": 3,
                "carrier": "peeroxide-hyperswarm-v3",
                "rendezvous_topic_hex": "44".repeat(32),
                "daemon_noise_public_key_hex": "55".repeat(32),
                "descriptor_generation": 9,
            },
        }));

        let status = serde_json::to_value(PublicResult::Status {
            device_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            daemon_boot_id: "boot-1".to_owned(), readiness: "ready".to_owned(),
            observed_at_unix: 1_700_000_000, active_turns: None,
        }).unwrap();
        assert_eq!(status, serde_json::json!({
            "state": "status",
            "device_id": "00000000-0000-0000-0000-000000000001",
            "daemon_boot_id": "boot-1",
            "readiness": "ready",
            "observed_at_unix": 1_700_000_000,
            "active_turns": null,
        }));

        let chat = serde_json::to_value(PublicResult::Chat(PublicChatResult {
            kind: "chat", schema_version: 3,
            request_id: "00000000-0000-7000-8000-000000000002".to_owned(),
            outcome: "accepted", records: Vec::new(),
            provider: Some("provider".to_owned()), model: Some("model".to_owned()),
        })).unwrap();
        assert_eq!(chat, serde_json::json!({
            "kind": "chat", "schema_version": 3,
            "request_id": "00000000-0000-7000-8000-000000000002",
            "outcome": "accepted", "records": [],
            "provider": "provider", "model": "model",
        }));

        let denied = serde_json::to_value(PublicResult::Denied { code: "device_denied" }).unwrap();
        assert_eq!(denied, serde_json::json!({ "state": "denied", "code": "device_denied" }));
    }

    #[test]
    fn terminal_codes_and_size_discovery_are_not_conflated() {
        assert_eq!(result_code(&PublicResult::Denied { code: "device_denied" }), 2);
        assert_eq!(result_code(&PublicResult::Failed { code: "transport_closed" }), 3);
        assert_eq!(result_code(&PublicResult::Cancelled), 4);
        assert_eq!(neoth_companion_operation_poll(std::ptr::null_mut(), std::ptr::null_mut(), 0, std::ptr::null_mut()), -1);
    }
}
