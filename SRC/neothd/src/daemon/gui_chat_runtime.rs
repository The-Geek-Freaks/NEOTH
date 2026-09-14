//! Daemon-owned W41 GUI chat producer.
//!
//! The audit-RPC route owns authentication and sealed decoding; this owner
//! owns the same-boot registry, staged GUI attachments, content-free durable
//! lifecycle ledger, replay and the one shared W39 provider admission.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::cli::chat_turn_pipeline::{
    ChatOutput, ChatTurnEvent, ChatTurnEventSink, ChatTurnTerminal,
};
use crate::daemon::audit_rpc::AuditStream;
use crate::daemon::chat_runtime::DaemonChatRuntime;
use crate::daemon::gui_chat_protocol::*;

const LEDGER_FILE: &str = "gui-chat-v1-ledger.jsonl";
const STAGING_DIRECTORY: &str = "gui-chat-v1-staging";
const REPLAY_FRAME_LIMIT: usize = 1024;
const REPLAY_BYTE_LIMIT: usize = GUI_CHAT_REPLAY_MAX_BYTES;
const EFFECT_HANDSHAKE_BOUND: Duration = Duration::from_secs(30);

/// Constructed once by `run_serve`, before the audit listener is published.
/// It never constructs a provider, writer or listener; `DaemonChatRuntime`
/// remains the sole W39/v1 provider permit and execution owner.
#[derive(Clone)]
pub(crate) struct DaemonGuiChatRuntime {
    core: Arc<DaemonChatRuntime>,
    home: Arc<PathBuf>,
    config_path: Arc<PathBuf>,
    boot_id: Arc<String>,
    state: Arc<Mutex<GuiRuntimeState>>,
    changed: Arc<Notify>,
    // This is synchronous because effect owners may be transferred from Drop.
    // Every such owner still lands in this same JoinSet and shutdown drains it.
    tasks: Arc<StdMutex<tokio::task::JoinSet<Uuid>>>,
}

struct GuiRuntimeState {
    accepting: bool,
    preflights: HashMap<String, Preflight>,
    turns: HashMap<Uuid, Turn>,
    ledger: BTreeMap<Uuid, LedgerRow>,
}

struct Preflight {
    request: GuiChatPreflightRequest,
    digest: GuiChatDigest,
    staged: Vec<Staged>,
    challenge: String,
    start_capability: Option<String>,
    ephemeral: Option<crate::consent::EphemeralConsent>,
}

struct Staged {
    ordinal: u16,
    digest: GuiChatDigest,
    path: PathBuf,
    ticket: String,
    binding: GuiChatDigest,
}

struct Turn {
    request_id: GuiChatRequestId,
    intent: GuiChatDigest,
    session: String,
    incognito: bool,
    cancellation: crate::cli::chat_turn_pipeline::ChatTurnCancellation,
    cancel_capability: String,
    grant: String,
    subscriptions: HashMap<GuiChatSurface, Subscription>,
    replay: VecDeque<Replay>,
    replay_bytes: usize,
    next_sequence: u64,
    phase: GuiChatPhase,
    terminal: Option<GuiChatTerminal>,
    effects: HashMap<u64, EffectRecord>,
    next_effect_id: u64,
    effect_admission: Arc<Mutex<()>>,
    effect_changed: Arc<Notify>,
    owner_registry: Arc<StdMutex<OwnerRegistry>>,
    staged: Vec<PathBuf>,
    ephemeral: Option<crate::consent::EphemeralConsent>,
}

struct Subscription {
    capability: String,
    generation: u64,
    cursor_upper_bound: u64,
}
struct Replay {
    sequence: u64,
    payload: GuiChatFramePayload,
    bytes: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LedgerRow {
    request_id: Uuid,
    intent_digest: String,
    provenance_digest: String,
    config_epoch: u64,
    receipt: String,
    terminal: Option<String>,
}

impl DaemonGuiChatRuntime {
    pub(crate) fn new(
        core: Arc<DaemonChatRuntime>,
        home: PathBuf,
        config_path: PathBuf,
        boot_id: String,
    ) -> Self {
        Self {
            core,
            home: Arc::new(home),
            config_path: Arc::new(config_path),
            boot_id: Arc::new(boot_id),
            state: Arc::new(Mutex::new(GuiRuntimeState {
                accepting: true,
                preflights: HashMap::new(),
                turns: HashMap::new(),
                ledger: BTreeMap::new(),
            })),
            changed: Arc::new(Notify::new()),
            tasks: Arc::new(StdMutex::new(tokio::task::JoinSet::new())),
        }
    }

    fn capability() -> String {
        Uuid::now_v7().simple().to_string()
    }
    fn reject(code: GuiChatErrorCode, detail: &'static str) -> GuiChatProtocolError {
        GuiChatProtocolError::Runtime(GuiChatErrorResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            code,
            retryable: false,
            detail: detail.into(),
        })
    }
    fn require_boot(&self, boot: &str) -> GuiChatResult<()> {
        if boot == self.boot_id.as_str() {
            Ok(())
        } else {
            Err(Self::reject(GuiChatErrorCode::BootChanged, "boot_changed"))
        }
    }
    fn staging_root(&self) -> PathBuf {
        self.home.join(STAGING_DIRECTORY)
    }
    fn ledger_path(&self) -> PathBuf {
        self.home.join(LEDGER_FILE)
    }

    async fn durable_lifecycle(&self, row: &LedgerRow) -> GuiChatResult<()> {
        // The companion WAL event is content-free and is ACKed before effect
        // admission. `EVENT_TYPE_GUI_CHAT_LIFECYCLE` is added by the WAL owner.
        let mut encoded = serde_json::to_vec(row)
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "ledger_encode"))?;
        self.core
            .append_gui_lifecycle(encoded.clone())
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "lifecycle_wal_ack"))?;
        let ledger_path = self.ledger_path();
        let parent = ledger_path.parent().expect("home joined file");
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "ledger_directory"))?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ledger_path)
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "ledger_open"))?;
        encoded.push(b'\n');
        file.write_all(&encoded)
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "ledger_write"))?;
        file.sync_data()
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "ledger_sync"))?;
        // No provider preparation is reached before both the typed WAL ACK and
        // this home-bound ledger durability boundary have completed.
        Ok(())
    }

    async fn stage(
        &self,
        request: &GuiChatPreflightRequest,
        digest: &GuiChatDigest,
    ) -> GuiChatResult<(Vec<GuiChatAttachmentManifestEntry>, Vec<Staged>)> {
        let candidates: Vec<PathBuf> = request
            .attachments
            .iter()
            .map(|a| PathBuf::from(&a.path))
            .collect();
        let loaded = crate::cli::chat::stage_daemon_gui_attachments(&candidates)
            .await
            .map_err(|_| {
                Self::reject(GuiChatErrorCode::AttachmentRejected, "attachment_admission")
            })?;
        let root = self.staging_root().join(Self::capability());
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "staging_directory"))?;
        let mut manifest = Vec::with_capacity(loaded.len());
        let mut staged = Vec::with_capacity(loaded.len());
        for (index, mut item) in loaded.into_iter().enumerate() {
            let ordinal = u16::try_from(index).map_err(|_| {
                Self::reject(GuiChatErrorCode::AttachmentRejected, "attachment_ordinal")
            })?;
            let content_digest = GuiChatDigest(hex::encode(Sha256::digest(&item.bytes)));
            let path = root.join(format!("{ordinal:04}.bin"));
            tokio::fs::write(&path, &item.bytes)
                .await
                .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "stage_write"))?;
            item.bytes.zeroize();
            let nonce = GuiChatDigest(hex::encode(Sha256::digest(Self::capability().as_bytes())));
            let binding = ticket_binding_digest(digest, ordinal, &content_digest, &nonce)?;
            let ticket = Self::capability();
            manifest.push(GuiChatAttachmentManifestEntry {
                ordinal,
                content_digest: content_digest.clone(),
                byte_len: item.byte_len,
                media_kind: item.media_kind,
            });
            staged.push(Staged {
                ordinal,
                digest: content_digest,
                path,
                ticket,
                binding,
            });
        }
        Ok((manifest, staged))
    }

    fn frame(turn: &mut Turn, payload: GuiChatFramePayload) -> Replay {
        let sequence = turn.next_sequence;
        turn.next_sequence = turn.next_sequence.saturating_add(1);
        let bytes = match &payload {
            GuiChatFramePayload::Delta { text } => text.len(),
            _ => 0,
        };
        Replay {
            sequence,
            payload,
            bytes,
        }
    }
    fn retain(turn: &mut Turn, frame: Replay) {
        turn.replay_bytes = turn.replay_bytes.saturating_add(frame.bytes);
        turn.replay.push_back(frame);
        while turn.replay.len() > REPLAY_FRAME_LIMIT || turn.replay_bytes > REPLAY_BYTE_LIMIT {
            if let Some(mut evicted) = turn.replay.pop_front() {
                if let GuiChatFramePayload::Delta { text } = &mut evicted.payload {
                    text.zeroize();
                }
                turn.replay_bytes = turn.replay_bytes.saturating_sub(evicted.bytes);
            }
        }
    }
    fn emit(turn: &mut Turn, payload: GuiChatFramePayload) {
        let frame = Self::frame(turn, payload);
        let upper = frame.sequence;
        Self::retain(turn, frame);
        for subscription in turn.subscriptions.values_mut() {
            subscription.cursor_upper_bound = upper;
        }
    }
    fn subscription_response(
        &self,
        id: GuiChatTurnId,
        session: String,
        surface: GuiChatSurface,
        s: &Subscription,
    ) -> GuiChatAttachExchangeResponse {
        GuiChatAttachExchangeResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: self.boot_id.to_string(),
            turn_id: id,
            session_id: session,
            surface,
            subscription_generation: s.generation,
            attach_capability: GuiChatOpaqueCapability(s.capability.clone()),
            initial_sequence: s.cursor_upper_bound,
        }
    }

    /// Schedule an admitted turn before releasing the state admission lock.
    /// This is synchronous: shutdown cannot observe an inserted turn without
    /// also finding its producer in the shared JoinSet.
    fn schedule_turn(&self, turn_id: Uuid) {
        let runtime = self.clone();
        self.tasks.lock().unwrap_or_else(|poison| poison.into_inner()).spawn(async move {
            let (message, model, skill, incognito, staged, cancel, effect_admission, ephemeral) = {
                let mut state = runtime.state.lock().await;
                let request_id = match state.turns.get(&turn_id) { Some(turn) => turn.request_id, None => return turn_id };
                // The canonical descriptor remains only in the preflight entry until
                // this point. It is removed immediately after the engine takes it.
                let preflight = match state.preflights.values().find(|p| p.request.request_id == request_id) { Some(p) => p, None => return turn_id };
                let (message, model, skill) = (preflight.request.message.clone(), preflight.request.model.clone(), preflight.request.skill_id.clone());
                let turn = match state.turns.get_mut(&turn_id) { Some(turn) => turn, None => return turn_id };
                (message, model, skill, turn.incognito, turn.staged.clone(), turn.cancellation.clone(), turn.effect_admission.clone(), turn.ephemeral.take())
            };
            let Some(ephemeral) = ephemeral else { return turn_id };
            let mut sink = RuntimeSink { runtime: runtime.clone(), turn_id, response: Sha256::new() };
            let effect_changed = {
                let state = runtime.state.lock().await;
                let Some(turn) = state.turns.get(&turn_id) else { return turn_id };
                turn.effect_changed.clone()
            };
            let owner_registry = { let state = runtime.state.lock().await; state.turns.get(&turn_id).expect("turn remains").owner_registry.clone() };
            let effect: Arc<dyn crate::providers::ChatTurnEffectGate> = Arc::new(RuntimeEffectGate { runtime: runtime.clone(), turn_id, effect_admission, effect_changed, owner_registry });
            let result = runtime.core.execute_gui_stream_turn(message, model, skill, incognito, staged, ephemeral, cancel, &mut sink, Some(effect)).await;
            let mut state = runtime.state.lock().await;
            let Some(turn) = state.turns.get_mut(&turn_id) else { return turn_id };
            let terminal = match result {
                Ok(ChatTurnTerminal::Complete { provider, model, .. }) => GuiChatTerminal { state: GuiChatTerminalState::Complete, response_digest: GuiChatDigest(hex::encode(sink.response.finalize())), provider, model, usage: GuiChatUsage { input_tokens: 0, output_tokens: 0, elapsed_ms: 0 }, lifecycle_receipt_id: GuiChatDigest(Self::capability()) },
                Err(_) => GuiChatTerminal { state: GuiChatTerminalState::Indeterminate, response_digest: GuiChatDigest(hex::encode(sink.response.finalize())), provider: "provider_indeterminate".into(), model: "accepted_model".into(), usage: GuiChatUsage { input_tokens: 0, output_tokens: 0, elapsed_ms: 0 }, lifecycle_receipt_id: GuiChatDigest(Self::capability()) },
            };
            turn.phase = GuiChatPhase::Finalizing;
            Self::emit(turn, GuiChatFramePayload::ProviderDone);
            turn.terminal = Some(terminal.clone());
            Self::emit(turn, GuiChatFramePayload::Terminal { terminal });
            runtime.changed.notify_waiters();
            turn_id
        });
    }

    /// Transfer an abandoned reservation/handshake to the daemon-owned task
    /// set.  This is deliberately not `tokio::spawn`: shutdown joins this set
    /// before it starts the shared W39/WAL drain.
    fn schedule_effect_settlement(&self, turn_id: Uuid, effect_id: u64, phase: EffectPhase) {
        let runtime = self.clone();
        let handle = tokio::runtime::Handle::try_current()
            .expect("W41 effect owner is dropped only from the daemon runtime");
        self.tasks
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .spawn_on(
                async move {
                    let _ = runtime.settle_effect(turn_id, effect_id, phase).await;
                    turn_id
                },
                &handle,
            );
    }

    #[cfg_attr(not(any(test, feature = "recursive-mas")), allow(dead_code))]
    fn schedule_effect_owner(
        &self,
        turn_id: Uuid,
        drain: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) {
        self.tasks
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .spawn(async move {
                drain.await;
                turn_id
            });
    }

    async fn force_effect_indeterminate(&self, turn_id: Uuid, effect_id: u64) {
        let (changed, owner_cancellations) = {
            let mut state = self.state.lock().await;
            let Some(turn) = state.turns.get_mut(&turn_id) else {
                return;
            };
            let Some(effect) = turn.effects.get_mut(&effect_id) else {
                return;
            };
            if matches!(
                effect.phase,
                EffectPhase::Started | EffectPhase::Aborted | EffectPhase::Indeterminate
            ) {
                (false, Vec::new())
            } else {
                effect.phase = EffectPhase::Indeterminate;
                effect.deadline = None;
                turn.cancellation.close();
                {
                    let mut registry = turn
                        .owner_registry
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    registry.closed = true;
                    (true, std::mem::take(&mut registry.cancellations))
                }
            }
        };
        for cancellation in owner_cancellations {
            cancellation.cancel();
        }
        if changed {
            self.changed.notify_waiters();
        }
    }

    async fn settle_effect(
        &self,
        turn_id: Uuid,
        effect_id: u64,
        next: EffectPhase,
    ) -> anyhow::Result<()> {
        let (kind, binding, receipt) = {
            let state = self.state.lock().await;
            let turn = state
                .turns
                .get(&turn_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI turn"))?;
            let effect = turn
                .effects
                .get(&effect_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI effect"))?;
            if matches!(
                effect.phase,
                EffectPhase::Started | EffectPhase::Aborted | EffectPhase::Indeterminate
            ) {
                return Ok(());
            }
            (
                effect.kind,
                effect.request_binding_sha256.clone(),
                effect.intent_receipt.clone(),
            )
        };
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": 1, "turn": turn_id, "effect": effect_id,
            "kind": format!("{kind:?}"), "binding": binding,
            "intent_receipt": receipt, "phase": next,
        }))?;
        if let Err(error) = self.core.append_gui_lifecycle(payload).await {
            // A response head/child spawn may already be known when Started's
            // ACK fails.  Preserve the failure as a closed indeterminate gate
            // so no retry/fallback can open another transport attempt.
            self.force_effect_indeterminate(turn_id, effect_id).await;
            return Err(error);
        }
        let (changed, owner_cancellations) = {
            let mut state = self.state.lock().await;
            let turn = state
                .turns
                .get_mut(&turn_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI turn"))?;
            let effect = turn
                .effects
                .get_mut(&effect_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI effect"))?;
            if matches!(
                effect.phase,
                EffectPhase::Started | EffectPhase::Aborted | EffectPhase::Indeterminate
            ) {
                (false, Vec::new())
            } else {
                effect.phase = next;
                effect.deadline = None;
                let owner_cancellations = if matches!(next, EffectPhase::Indeterminate) {
                    turn.cancellation.close();
                    let mut registry = turn
                        .owner_registry
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    registry.closed = true;
                    std::mem::take(&mut registry.cancellations)
                } else {
                    Vec::new()
                };
                (true, owner_cancellations)
            }
        };
        for cancellation in owner_cancellations {
            cancellation.cancel();
        }
        if changed {
            self.changed.notify_waiters();
        }
        Ok(())
    }

    async fn close_effect_admission_and_settle(&self, turn_id: Uuid) -> GuiChatResult<()> {
        let admission = {
            let state = self.state.lock().await;
            state
                .turns
                .get(&turn_id)
                .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?
                .effect_admission
                .clone()
        };
        let _serial = admission.lock().await;
        let (preparing, deadlines, owner_cancellations) = {
            let mut state = self.state.lock().await;
            let turn = state
                .turns
                .get_mut(&turn_id)
                .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
            turn.cancellation.close();
            let preparing = turn
                .effects
                .iter()
                .filter_map(|(id, effect)| {
                    matches!(effect.phase, EffectPhase::Preparing).then_some(*id)
                })
                .collect::<Vec<_>>();
            let deadlines = turn
                .effects
                .values()
                .filter_map(|effect| {
                    (matches!(effect.phase, EffectPhase::Handshaking)).then_some(effect.deadline)
                })
                .collect::<Vec<_>>();
            let mut registry = turn
                .owner_registry
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            registry.closed = true;
            (
                preparing,
                deadlines,
                std::mem::take(&mut registry.cancellations),
            )
        };
        for cancellation in owner_cancellations {
            cancellation.cancel();
        }
        self.changed.notify_waiters();
        for effect_id in preparing {
            self.settle_effect(turn_id, effect_id, EffectPhase::Aborted)
                .await
                .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "effect_abort_wal_ack"))?;
        }
        // A handshake owner remains running.  Wait only to its named deadline;
        // after that the concrete outcome is unknown and must block all later
        // starts while the producer/owner task continues its safe drain.
        for deadline in deadlines.into_iter().flatten() {
            loop {
                let notified = self.changed.notified();
                let handshaking = {
                    let state = self.state.lock().await;
                    state.turns.get(&turn_id).is_some_and(|turn| {
                        turn.effects
                            .values()
                            .any(|effect| matches!(effect.phase, EffectPhase::Handshaking))
                    })
                };
                if !handshaking {
                    break;
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    let pending = {
                        let state = self.state.lock().await;
                        state
                            .turns
                            .get(&turn_id)
                            .map(|turn| {
                                turn.effects
                                    .iter()
                                    .filter_map(|(id, effect)| {
                                        matches!(effect.phase, EffectPhase::Handshaking)
                                            .then_some(*id)
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    };
                    for effect_id in pending {
                        self.force_effect_indeterminate(turn_id, effect_id).await;
                    }
                    break;
                }
            }
        }
        Ok(())
    }
}

struct RuntimeSink {
    runtime: DaemonGuiChatRuntime,
    turn_id: Uuid,
    response: Sha256,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum EffectPhase {
    Preparing,
    Handshaking,
    Started,
    Aborted,
    Indeterminate,
}
struct EffectRecord {
    phase: EffectPhase,
    kind: crate::providers::ChatTurnEffectKind,
    request_binding_sha256: String,
    accepted_epoch: u64,
    provider_identity: String,
    intent_receipt: String,
    deadline: Option<tokio::time::Instant>,
}
struct OwnerRegistry {
    closed: bool,
    cancellations: Vec<crate::providers::EffectOwnerCancellation>,
}
struct RuntimeEffectGate {
    runtime: DaemonGuiChatRuntime,
    turn_id: Uuid,
    effect_admission: Arc<Mutex<()>>,
    effect_changed: Arc<Notify>,
    #[cfg_attr(not(any(test, feature = "recursive-mas")), allow(dead_code))]
    owner_registry: Arc<StdMutex<OwnerRegistry>>,
}
struct RuntimePreparingEffect {
    runtime: DaemonGuiChatRuntime,
    turn_id: Uuid,
    effect_id: u64,
    effect_admission: Arc<Mutex<()>>,
    effect_changed: Arc<Notify>,
    armed: bool,
}
struct RuntimeEffectLease {
    runtime: DaemonGuiChatRuntime,
    turn_id: Uuid,
    effect_id: u64,
    deadline: tokio::time::Instant,
    armed: bool,
}
#[async_trait]
impl crate::providers::ChatTurnEffectGate for RuntimeEffectGate {
    async fn intent(
        &self,
        kind: crate::providers::ChatTurnEffectKind,
        binding: &str,
    ) -> anyhow::Result<crate::providers::PreparingEffect> {
        let _admission = self.effect_admission.lock().await;
        let authority = self.runtime.core.recheck_gui_effect_authority()?;
        let (effect_id, intent_receipt) = {
            let mut state = self.runtime.state.lock().await;
            let turn = state
                .turns
                .get_mut(&self.turn_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI turn"))?;
            turn.cancellation.check_open("ADR-010 effect intent")?;
            let effect_id = turn.next_effect_id;
            turn.next_effect_id = turn.next_effect_id.saturating_add(1);
            (effect_id, DaemonGuiChatRuntime::capability())
        };
        // Hold the same admission lock from closed-state observation through
        // the durable Intent ACK and reservation publication.  Cancel cannot
        // return Accepted between any two of these steps.
        let intent = serde_json::to_vec(&serde_json::json!({
            "schema": 1, "turn": self.turn_id, "effect": effect_id,
            "kind": format!("{kind:?}"), "binding": binding,
            "config_epoch": authority.config_epoch,
            "provider": authority.provider_identity,
            "receipt": intent_receipt, "phase": "intent"
        }))?;
        self.runtime.core.append_gui_lifecycle(intent).await?;
        let mut state = self.runtime.state.lock().await;
        let turn = state
            .turns
            .get_mut(&self.turn_id)
            .ok_or_else(|| anyhow::anyhow!("unknown GUI turn"))?;
        turn.cancellation.check_open("ADR-010 effect intent")?;
        turn.effects.insert(
            effect_id,
            EffectRecord {
                phase: EffectPhase::Preparing,
                kind,
                request_binding_sha256: binding.to_owned(),
                accepted_epoch: authority.config_epoch,
                provider_identity: authority.provider_identity,
                intent_receipt,
                deadline: None,
            },
        );
        Ok(crate::providers::PreparingEffect::new(Box::new(
            RuntimePreparingEffect {
                runtime: self.runtime.clone(),
                turn_id: self.turn_id,
                effect_id,
                effect_admission: self.effect_admission.clone(),
                effect_changed: self.effect_changed.clone(),
                armed: true,
            },
        )))
    }

    fn register_owner(
        &self,
        owner: crate::providers::TurnEffectOwner,
    ) -> crate::providers::EffectOwnerRegistration {
        let (drain, cancellation) = owner.into_parts();
        let closed = {
            let mut registry = self
                .owner_registry
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let closed = registry.closed;
            if !closed {
                registry.cancellations.push(cancellation.clone());
            }
            // Keep registration serialized with registry closure until the
            // owner is physically in the shutdown JoinSet.
            self.runtime.schedule_effect_owner(self.turn_id, drain);
            closed
        };
        if closed {
            cancellation.cancel();
            return crate::providers::EffectOwnerRegistration::Transferred {
                error: anyhow::anyhow!("GUI effect owner registration closed"),
            };
        }
        crate::providers::EffectOwnerRegistration::Registered
    }
}
#[async_trait]
impl crate::providers::PreparingEffectLifecycle for RuntimePreparingEffect {
    async fn begin_start(
        mut self: Box<Self>,
        start_authority: Option<&dyn crate::providers::EffectStartAuthority>,
    ) -> anyhow::Result<crate::providers::EffectStartLease> {
        let _admission = self.effect_admission.lock().await;
        let authority = self.runtime.core.recheck_gui_effect_authority()?;
        let deadline = tokio::time::Instant::now() + EFFECT_HANDSHAKE_BOUND;
        let denied = {
            let mut state = self.runtime.state.lock().await;
            let turn = state
                .turns
                .get_mut(&self.turn_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI turn"))?;
            turn.cancellation.check_open("ADR-010 effect start")?;
            let effect = turn
                .effects
                .get_mut(&self.effect_id)
                .ok_or_else(|| anyhow::anyhow!("unknown GUI effect"))?;
            anyhow::ensure!(
                matches!(effect.phase, EffectPhase::Preparing),
                "effect is not preparing"
            );
            anyhow::ensure!(
                effect.accepted_epoch == authority.config_epoch
                    && effect.provider_identity == authority.provider_identity,
                "GUI effect authority changed before start"
            );
            // This synchronous recheck is intentionally inside the same
            // admission critical section as cancellation, identity/epoch
            // validation and the Handshaking transition.  Thus a successful
            // AllowOnce spend cannot leave an await-sized gap before the
            // concrete adapter owns the reservation.
            match start_authority {
                Some(start_authority) => match start_authority.recheck() {
                    Err(error) => Some(error),
                    Ok(()) => {
                        effect.phase = EffectPhase::Handshaking;
                        effect.deadline = Some(deadline);
                        None
                    }
                },
                None => {
                    effect.phase = EffectPhase::Handshaking;
                    effect.deadline = Some(deadline);
                    None
                }
            }
        };
        if let Some(error) = denied {
            // Intent is already durable, but no transport lease was issued.
            // Record the known pre-start refusal synchronously; scheduling it
            // through Drop would make a caller observe the consent error before
            // the paired Aborted record exists.
            self.armed = false;
            self.runtime
                .settle_effect(self.turn_id, self.effect_id, EffectPhase::Aborted)
                .await
                .map_err(|settlement| anyhow::anyhow!(
                    "live consent rejected before effect start: {error}; durable abort settlement failed: {settlement}"
                ))?;
            self.effect_changed.notify_waiters();
            return Err(error);
        }
        self.armed = false;
        self.effect_changed.notify_waiters();
        Ok(crate::providers::EffectStartLease::new(Box::new(
            RuntimeEffectLease {
                runtime: self.runtime.clone(),
                turn_id: self.turn_id,
                effect_id: self.effect_id,
                deadline,
                armed: true,
            },
        )))
    }

    fn abandon(mut self: Box<Self>) {
        if self.armed {
            self.runtime.schedule_effect_settlement(
                self.turn_id,
                self.effect_id,
                EffectPhase::Aborted,
            );
            self.armed = false;
        }
    }
}
impl Drop for RuntimePreparingEffect {
    fn drop(&mut self) {
        if self.armed {
            self.runtime.schedule_effect_settlement(
                self.turn_id,
                self.effect_id,
                EffectPhase::Aborted,
            );
            self.armed = false;
        }
    }
}
#[async_trait]
impl crate::providers::EffectStartLeaseLifecycle for RuntimeEffectLease {
    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    async fn settle_started(self: Box<Self>) -> anyhow::Result<()> {
        self.settle(EffectPhase::Started).await
    }
    async fn settle_aborted_proven_pre_start(self: Box<Self>) -> anyhow::Result<()> {
        self.settle(EffectPhase::Aborted).await
    }
    async fn settle_indeterminate(self: Box<Self>) -> anyhow::Result<()> {
        self.settle(EffectPhase::Indeterminate).await
    }

    fn abandon(mut self: Box<Self>) {
        if self.armed {
            self.runtime.schedule_effect_settlement(
                self.turn_id,
                self.effect_id,
                EffectPhase::Indeterminate,
            );
            self.armed = false;
        }
    }
}
impl Drop for RuntimeEffectLease {
    fn drop(&mut self) {
        if self.armed {
            self.runtime.schedule_effect_settlement(
                self.turn_id,
                self.effect_id,
                EffectPhase::Indeterminate,
            );
            self.armed = false;
        }
    }
}
impl RuntimeEffectLease {
    async fn settle(mut self: Box<Self>, next: EffectPhase) -> anyhow::Result<()> {
        let result = self
            .runtime
            .settle_effect(self.turn_id, self.effect_id, next)
            .await;
        self.armed = false;
        result
    }
}
impl ChatTurnEventSink for RuntimeSink {
    fn emit(&mut self, event: ChatTurnEvent) -> anyhow::Result<()> {
        let mut state = self.runtime.state.blocking_lock();
        let Some(turn) = state.turns.get_mut(&self.turn_id) else {
            anyhow::bail!("GUI turn was removed")
        };
        match event {
            ChatTurnEvent::Output(ChatOutput::ProviderDelta { text, .. }) => {
                self.response.update(text.as_bytes());
                DaemonGuiChatRuntime::emit(turn, GuiChatFramePayload::Delta { text });
            }
            ChatTurnEvent::Output(
                ChatOutput::Notice { text, .. } | ChatOutput::HumanStderr { text },
            ) => DaemonGuiChatRuntime::emit(
                turn,
                GuiChatFramePayload::Notice {
                    code: crate::security::redact::sanitize_tool_output(&text),
                },
            ),
            ChatTurnEvent::Output(_) => {}
            ChatTurnEvent::Terminal(_) => {}
        }
        self.runtime.changed.notify_waiters();
        Ok(())
    }
}

#[async_trait]
impl GuiChatRuntime for DaemonGuiChatRuntime {
    async fn preflight(
        &self,
        request: GuiChatPreflightRequest,
    ) -> GuiChatResult<GuiChatPreflightResponse> {
        validate_preflight_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        // The GUI must project the core-owned challenge record rather than
        // minting a look-alike UUID.  The dotted id.secret is later consumed by
        // the existing request-bound verifier in `decide`.
        let consent = crate::cli::consent_challenge::create_core_gui_chat_consent_preflight(
            &self.home,
            crate::time::now_unix_secs(),
        )
        .map_err(|_| Self::reject(GuiChatErrorCode::ConsentRequired, "consent_preflight"))?;
        let (challenge, consent) = match consent {
            crate::cli::consent_challenge::CoreGuiChatConsentPreflight::Ready => (
                // This opaque value is deliberately not accepted as a proof;
                // `Ready` has no challenge record and requires no decision.
                Self::capability(),
                GuiChatConsentPreflightState::Ready,
            ),
            crate::cli::consent_challenge::CoreGuiChatConsentPreflight::ConfirmationRequired {
                challenge_token,
                routes,
                expires_at_unix_ms,
            } => (
                challenge_token.to_string(),
                GuiChatConsentPreflightState::ConfirmationRequired {
                    prompt: GuiChatConsentPromptWire {
                        request_id: request.request_id,
                        routes: routes
                            .into_iter()
                            .map(|route| GuiChatConsentRouteWire {
                                provider: route.provider,
                                endpoint_origin: route.endpoint_origin,
                            })
                            .collect(),
                        expires_at_unix_ms,
                    },
                },
            ),
        };
        let provisional = preflight_descriptor_digest(
            &request,
            &[],
            0,
            request.incognito.then_some(self.boot_id.as_bytes()),
        )?;
        let (manifest, mut staged) = self.stage(&request, &provisional).await?;
        let epoch = self
            .core
            .accepted_config_epoch()
            .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "provider_epoch"))?;
        let digest = preflight_descriptor_digest(
            &request,
            &manifest,
            epoch,
            request.incognito.then_some(self.boot_id.as_bytes()),
        )?;
        // Stage first, then mint new tickets bound to the final descriptor.
        // The provisional value is never published or accepted as authority.
        for staged_attachment in &mut staged {
            let nonce = GuiChatDigest(hex::encode(Sha256::digest(Self::capability().as_bytes())));
            staged_attachment.binding = ticket_binding_digest(
                &digest,
                staged_attachment.ordinal,
                &staged_attachment.digest,
                &nonce,
            )?;
            staged_attachment.ticket = Self::capability();
        }
        let id = Self::capability();
        self.state.lock().await.preflights.insert(
            id.clone(),
            Preflight {
                request,
                digest: digest.clone(),
                staged,
                challenge: challenge.clone(),
                start_capability: None,
                ephemeral: None,
            },
        );
        Ok(GuiChatPreflightResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: self.boot_id.to_string(),
            preflight_id: GuiChatOpaqueCapability(id),
            preflight_descriptor_digest: digest,
            consent_challenge: GuiChatOpaqueCapability(challenge),
            attachment_manifest: manifest,
            consent,
        })
    }
    async fn decide(
        &self,
        request: GuiChatConsentDecisionRequest,
    ) -> GuiChatResult<GuiChatConsentDecisionResponse> {
        validate_decide_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        if matches!(request.decision, GuiChatConsentDecision::Deny) {
            return Ok(GuiChatConsentDecisionResponse::Denied {
                schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                expected_boot_id: self.boot_id.as_ref().clone(),
            });
        }
        let mut state = self.state.lock().await;
        let preflight = state
            .preflights
            .get_mut(&request.preflight_id.0)
            .ok_or_else(|| Self::reject(GuiChatErrorCode::ConsentRequired, "unknown_preflight"))?;
        if preflight.digest != request.preflight_descriptor_digest
            || preflight.challenge != request.consent_challenge.0
        {
            return Err(Self::reject(
                GuiChatErrorCode::ConsentRequired,
                "descriptor_or_challenge",
            ));
        }
        let proof = request
            .consent_proof
            .as_ref()
            .ok_or_else(|| Self::reject(GuiChatErrorCode::ConsentRequired, "consent_proof"))?;
        let consumed = crate::cli::consent_challenge::consume_request_bound_gui_chat_consent(
            &self.home,
            &self.config_path,
            &proof.0,
            &preflight.digest.0,
            &preflight.challenge,
            &preflight.request.session_id,
            crate::time::now_unix_secs(),
        )
        .map_err(|_| Self::reject(GuiChatErrorCode::ConsentRequired, "consent_proof"))?;
        preflight.ephemeral = Some(consumed.ephemeral);
        let bindings: Vec<GuiChatStagedAttachmentBinding> = preflight
            .staged
            .iter()
            .map(|s| GuiChatStagedAttachmentBinding {
                ordinal: s.ordinal,
                content_digest: s.digest.clone(),
                ticket_binding_digest: s.binding.clone(),
            })
            .collect();
        let intent = turn_intent_digest(&preflight.digest, &bindings)?;
        let start_capability = Self::capability();
        preflight.start_capability = Some(start_capability.clone());
        Ok(GuiChatConsentDecisionResponse::Approved {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: self.boot_id.as_ref().clone(),
            turn_intent_digest: intent,
            start_capability: GuiChatOpaqueCapability(start_capability),
            attachment_tickets: preflight
                .staged
                .iter()
                .map(|s| GuiChatAttachmentTicket {
                    ordinal: s.ordinal,
                    ticket: GuiChatOpaqueCapability(s.ticket.clone()),
                })
                .collect(),
        })
    }
    async fn start(&self, request: GuiChatStartRequest) -> GuiChatResult<GuiChatStartResponse> {
        validate_start_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        let response = {
            let mut state = self.state.lock().await;
            if !state.accepting {
                return Err(Self::reject(
                    GuiChatErrorCode::Unavailable,
                    "runtime_closing",
                ));
            }
            if let Some((existing_id, existing)) = state
                .turns
                .iter()
                .find(|(_, t)| t.request_id == request.request_id)
            {
                if existing.intent == request.turn_intent_digest {
                    return Ok(GuiChatStartResponse {
                        schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                        expected_boot_id: self.boot_id.to_string(),
                        turn_id: GuiChatTurnId(*existing_id),
                        turn_intent_digest: existing.intent.clone(),
                        origin_attach_capability: GuiChatOpaqueCapability(String::new()),
                        cancel_capability: GuiChatOpaqueCapability(
                            existing.cancel_capability.clone(),
                        ),
                        same_session_attach_grant: GuiChatSameSessionAttachGrant {
                            grant: GuiChatOpaqueCapability(existing.grant.clone()),
                            turn_id: GuiChatTurnId(*existing_id),
                            session_id: existing.session.clone(),
                            allowed_surfaces: vec![GuiChatSurface::Main, GuiChatSurface::Buddy],
                        },
                        initial_sequence: existing.next_sequence.saturating_sub(1),
                    });
                }
                return Err(Self::reject(
                    GuiChatErrorCode::Conflict,
                    "request_digest_conflict",
                ));
            }
            let matching_preflight = state
                .preflights
                .iter()
                .find_map(|(id, preflight)| {
                    (preflight.start_capability.as_deref()
                        == Some(request.start_capability.0.as_str()))
                    .then_some(id.clone())
                })
                .ok_or_else(|| {
                    Self::reject(GuiChatErrorCode::ConsentRequired, "start_capability")
                })?;
            let preflight = state
                .preflights
                .remove(&matching_preflight)
                .expect("matched preflight remains owned");
            if preflight.request.request_id != request.request_id
                || preflight.digest.0.is_empty()
                || request.attachment_tickets.len() != preflight.staged.len()
                || request
                    .attachment_tickets
                    .iter()
                    .zip(&preflight.staged)
                    .any(|(t, s)| t.ordinal != s.ordinal || t.ticket.0 != s.ticket)
            {
                return Err(Self::reject(
                    GuiChatErrorCode::Unauthorized,
                    "ticket_binding",
                ));
            }
            let id = Uuid::now_v7();
            let grant = Self::capability();
            let provenance = GuiChatDigest(hex::encode(Sha256::digest(
                format!(
                    "{}:{:?}",
                    preflight.request.session_id, preflight.request.origin_surface
                )
                .as_bytes(),
            )));
            let epoch = self
                .core
                .accepted_config_epoch()
                .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "provider_epoch"))?;
            let row = LedgerRow {
                request_id: request.request_id.0,
                intent_digest: request.turn_intent_digest.0.clone(),
                provenance_digest: provenance.0,
                config_epoch: epoch,
                receipt: Self::capability(),
                terminal: None,
            };
            self.durable_lifecycle(&row).await?;
            state.ledger.insert(request.request_id.0, row);
            let turn = Turn {
                request_id: request.request_id,
                intent: request.turn_intent_digest.clone(),
                session: request.session_id.clone(),
                incognito: preflight.request.incognito,
                cancellation: Default::default(),
                cancel_capability: Self::capability(),
                grant: grant.clone(),
                subscriptions: HashMap::new(),
                replay: VecDeque::new(),
                replay_bytes: 0,
                next_sequence: 1,
                phase: GuiChatPhase::Waiting,
                terminal: None,
                effects: HashMap::new(),
                next_effect_id: 1,
                effect_admission: Arc::new(Mutex::new(())),
                effect_changed: Arc::new(Notify::new()),
                owner_registry: Arc::new(StdMutex::new(OwnerRegistry {
                    closed: false,
                    cancellations: Vec::new(),
                })),
                staged: preflight.staged.iter().map(|s| s.path.clone()).collect(),
                ephemeral: preflight.ephemeral,
            };
            state.turns.insert(id, turn);
            let response = {
                let turn = state.turns.get_mut(&id).expect("inserted turn");
                Self::emit(turn, GuiChatFramePayload::Accepted);
                GuiChatStartResponse {
                    schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: self.boot_id.to_string(),
                    turn_id: GuiChatTurnId(id),
                    turn_intent_digest: turn.intent.clone(),
                    origin_attach_capability: GuiChatOpaqueCapability(String::new()),
                    cancel_capability: GuiChatOpaqueCapability(turn.cancel_capability.clone()),
                    same_session_attach_grant: GuiChatSameSessionAttachGrant {
                        grant: GuiChatOpaqueCapability(grant),
                        turn_id: GuiChatTurnId(id),
                        session_id: turn.session.clone(),
                        allowed_surfaces: vec![GuiChatSurface::Main, GuiChatSurface::Buddy],
                    },
                    initial_sequence: turn.next_sequence.saturating_sub(1),
                }
            };
            self.schedule_turn(id);
            response
        };
        Ok(response)
    }
    async fn exchange_attach(
        &self,
        request: GuiChatAttachExchangeRequest,
    ) -> GuiChatResult<GuiChatAttachExchangeResponse> {
        validate_attach_exchange_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        let mut state = self.state.lock().await;
        let t = state
            .turns
            .get_mut(&request.turn_id.0)
            .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
        if t.session != request.session_id || t.grant != request.grant.0 {
            return Err(Self::reject(GuiChatErrorCode::Forbidden, "attach_grant"));
        }
        if !matches!(
            request.desired_surface,
            GuiChatSurface::Main | GuiChatSurface::Buddy
        ) {
            return Err(Self::reject(GuiChatErrorCode::Forbidden, "attach_surface"));
        }
        if !t.subscriptions.contains_key(&request.desired_surface) {
            let s = Subscription {
                capability: Self::capability(),
                generation: 1,
                cursor_upper_bound: t.next_sequence.saturating_sub(1),
            };
            t.subscriptions.insert(request.desired_surface, s);
        }
        Ok(self.subscription_response(
            request.turn_id,
            request.session_id,
            request.desired_surface,
            t.subscriptions
                .get(&request.desired_surface)
                .expect("subscription is present"),
        ))
    }
    async fn attach(
        &self,
        mut stream: AuditStream,
        request: GuiChatAttachRequest,
    ) -> GuiChatResult<()> {
        self.require_boot(&request.expected_boot_id)?;
        let mut cursor = request.after_sequence;
        // The server has transferred from its ordinary ingress permit to a
        // bounded attach permit before calling us. Slow output therefore only
        // drops this subscription; it never owns the provider permit or turn.
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(head))
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "attach_write_timeout"))?
            .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "attach_write"))?;
        loop {
            let (frames, terminal) = {
                let state = self.state.lock().await;
                let turn = state
                    .turns
                    .get(&request.turn_id.0)
                    .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
                let subscription = turn
                    .subscriptions
                    .get(&request.surface)
                    .ok_or_else(|| Self::reject(GuiChatErrorCode::Forbidden, "subscription"))?;
                validate_attach_request(&request, subscription.cursor_upper_bound)?;
                if turn.session != request.session_id
                    || subscription.capability != request.attach_capability.0
                    || subscription.generation != request.subscription_generation
                {
                    return Err(Self::reject(
                        GuiChatErrorCode::Forbidden,
                        "attach_capability",
                    ));
                }
                let earliest = turn
                    .replay
                    .front()
                    .map(|frame| frame.sequence.saturating_sub(1))
                    .unwrap_or(0);
                if cursor < earliest {
                    return Err(Self::reject(GuiChatErrorCode::ReplayGap, "replay_gap"));
                }
                let frames = turn
                    .replay
                    .iter()
                    .filter(|frame| frame.sequence > cursor)
                    .map(|frame| GuiChatStreamFrame {
                        schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                        boot_id: self.boot_id.to_string(),
                        turn_id: request.turn_id.clone(),
                        subscription: GuiChatSubscription {
                            session_id: request.session_id.clone(),
                            surface: request.surface,
                            generation: request.subscription_generation,
                        },
                        sequence: frame.sequence,
                        payload: frame.payload.clone(),
                    })
                    .collect::<Vec<_>>();
                (frames, turn.terminal.is_some())
            };
            for frame in frames {
                validate_stream_frame(&frame)?;
                let mut line = serde_json::to_vec(&frame)
                    .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "frame_encode"))?;
                line.push(b'\n');
                cursor = frame.sequence;
                tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(&line))
                    .await
                    .map_err(|_| {
                        Self::reject(GuiChatErrorCode::Unavailable, "attach_write_timeout")
                    })?
                    .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "attach_write"))?;
            }
            if terminal {
                stream
                    .shutdown()
                    .await
                    .map_err(|_| Self::reject(GuiChatErrorCode::Unavailable, "attach_close"))?;
                return Ok(());
            }
            self.changed.notified().await;
        }
    }
    async fn cancel(&self, request: GuiChatCancelRequest) -> GuiChatResult<GuiChatCancelResponse> {
        validate_cancel_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        {
            let state = self.state.lock().await;
            let turn = state
                .turns
                .get(&request.turn_id.0)
                .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
            if turn.session != request.session_id
                || turn.cancel_capability != request.cancel_capability.0
            {
                return Err(Self::reject(
                    GuiChatErrorCode::Forbidden,
                    "cancel_capability",
                ));
            }
            if turn.terminal.is_some() {
                return Ok(GuiChatCancelResponse {
                    schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                    outcome: GuiChatCancelOutcome::AlreadyTerminal,
                });
            }
        }
        self.close_effect_admission_and_settle(request.turn_id.0)
            .await?;
        let receipt = Self::capability();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": 1, "turn": request.turn_id.0, "phase": "cancel_requested", "receipt": receipt,
        }))
        .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "cancel_encode"))?;
        self.core
            .append_gui_lifecycle(payload)
            .await
            .map_err(|_| Self::reject(GuiChatErrorCode::Internal, "cancel_wal_ack"))?;
        let mut state = self.state.lock().await;
        let turn = state
            .turns
            .get_mut(&request.turn_id.0)
            .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
        Self::emit(turn, GuiChatFramePayload::CancelRequested);
        self.changed.notify_waiters();
        Ok(GuiChatCancelResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            outcome: GuiChatCancelOutcome::Accepted,
        })
    }
    async fn status(&self, request: GuiChatStatusRequest) -> GuiChatResult<GuiChatStatusResponse> {
        validate_status_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        let state = self.state.lock().await;
        let t = state
            .turns
            .get(&request.turn_id.0)
            .ok_or_else(|| Self::reject(GuiChatErrorCode::Unavailable, "unknown_turn"))?;
        let permitted = t
            .subscriptions
            .values()
            .any(|s| s.capability == request.attach_capability.0);
        if t.session != request.session_id || !permitted {
            return Err(Self::reject(
                GuiChatErrorCode::Forbidden,
                "status_capability",
            ));
        }
        Ok(GuiChatStatusResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: self.boot_id.to_string(),
            turn_id: request.turn_id,
            phase: t.phase,
            latest_sequence: t.next_sequence.saturating_sub(1),
            terminal: t.terminal.clone(),
        })
    }
    async fn active(&self, request: GuiChatActiveRequest) -> GuiChatResult<GuiChatActiveResponse> {
        validate_active_request(&request)?;
        self.require_boot(&request.expected_boot_id)?;
        let state = self.state.lock().await;
        let active = state
            .turns
            .iter()
            .find(|(_, t)| {
                t.session == request.session_id
                    && t.grant == request.same_session_attach_grant.0
                    && t.terminal.is_none()
            })
            .map(|(id, t)| GuiChatActiveTurn {
                turn_id: GuiChatTurnId(*id),
                phase: t.phase,
                latest_sequence: t.next_sequence.saturating_sub(1),
            });
        Ok(GuiChatActiveResponse {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: self.boot_id.to_string(),
            active_turn: active,
        })
    }
    async fn close_and_drain(&self) {
        let turn_ids = {
            let mut state = self.state.lock().await;
            state.accepting = false;
            state.turns.keys().copied().collect::<Vec<_>>()
        };
        for turn_id in turn_ids {
            // The same close path serializes cancellation with a preparing
            // lease and owns bounded settlement before any producer join.
            let _ = self.close_effect_admission_and_settle(turn_id).await;
        }
        // Runtime tasks are never detached: all producer tasks settle before
        // W39's global writer drain can begin.
        loop {
            let mut tasks = {
                let mut shared = self
                    .tasks
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                std::mem::replace(&mut *shared, tokio::task::JoinSet::new())
            };
            if tasks.is_empty() {
                break;
            }
            while tasks.join_next().await.is_some() {}
        }
        let staged = {
            let mut state = self.state.lock().await;
            let mut staged = Vec::new();
            for turn in state.turns.values_mut() {
                for frame in &mut turn.replay {
                    if let GuiChatFramePayload::Delta { text } = &mut frame.payload {
                        text.zeroize();
                    }
                }
                staged.append(&mut turn.staged);
            }
            staged
        };
        for path in staged {
            let _ = tokio::fs::remove_file(path).await;
        }
        self.core.close_and_drain().await;
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::config::reload::ReloadController;
    use crate::providers::{
        ChatTurnEffectGate, Completion, EffectOwnerCancellation, Provider, Request, TurnEffectOwner,
    };
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FixtureProvider;

    /// Stands in for the private provider live-consent callback after its
    /// durable route or shared AllowOnce capability changes post-Intent.
    struct PostIntentConsentRevoked;

    struct PausedIntentGate {
        inner: RuntimeEffectGate,
        intent_acked: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl crate::providers::ChatTurnEffectGate for PausedIntentGate {
        async fn intent(
            &self,
            kind: crate::providers::ChatTurnEffectKind,
            binding: &str,
        ) -> anyhow::Result<crate::providers::PreparingEffect> {
            let preparing = self.inner.intent(kind, binding).await?;
            // `notify_one` retains a permit if the test has not yet polled
            // its waiter, so the post-Intent pause cannot lose either signal.
            self.intent_acked.notify_one();
            self.release.notified().await;
            Ok(preparing)
        }

        fn register_owner(
            &self,
            owner: crate::providers::TurnEffectOwner,
        ) -> crate::providers::EffectOwnerRegistration {
            self.inner.register_owner(owner)
        }
    }

    impl crate::providers::EffectStartAuthority for PostIntentConsentRevoked {
        fn recheck(&self) -> anyhow::Result<()> {
            anyhow::bail!("fixture: exact live consent was revoked after Intent ACK")
        }
    }

    #[async_trait]
    impl Provider for FixtureProvider {
        fn name(&self) -> &'static str {
            "claude_cli"
        }
        fn default_model(&self) -> Option<&str> {
            Some("w41-fixture")
        }
        async fn complete(&self, _request: Request) -> anyhow::Result<Completion> {
            unreachable!("the lifecycle fixture never enters provider body work")
        }
    }

    async fn runtime_with_handshake_turn() -> (
        DaemonGuiChatRuntime,
        Uuid,
        crate::wal::writer::WalWriterCompletion,
        tempfile::TempDir,
    ) {
        let home = tempfile::tempdir().expect("fixture home");
        let mut config = crate::config::FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_model: Some("w41-fixture".into()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("fixture config"),
        )
        .expect("write fixture config");
        let segment = home.path().join("wal").join("000001.wal");
        std::fs::create_dir_all(segment.parent().expect("wal parent")).expect("create wal parent");
        let (writer, completion, ready) = crate::wal::writer::spawn_for_home_ready_with_completion(
            segment.clone(),
            home.path().to_path_buf(),
        )
        .expect("spawn real fixture writer");
        ready.wait().await.expect("fixture writer ready");
        let controller = Arc::new(ReloadController::new(config, config_path.clone()));
        let core = Arc::new(DaemonChatRuntime::new(
            home.path().to_path_buf(),
            config_path,
            segment,
            controller,
            writer,
        ));
        core.publish_provider(Arc::new(FixtureProvider) as Arc<dyn Provider>, 0)
            .await
            .expect("publish fixture provider");
        let runtime = DaemonGuiChatRuntime::new(
            core,
            home.path().to_path_buf(),
            home.path().join("freedom.yaml"),
            "fixture-boot".into(),
        );
        let turn_id = Uuid::now_v7();
        let request_id = GuiChatRequestId(Uuid::now_v7());
        runtime.state.lock().await.turns.insert(
            turn_id,
            Turn {
                request_id,
                intent: GuiChatDigest("0".repeat(64)),
                session: "fixture".into(),
                incognito: false,
                cancellation: Default::default(),
                cancel_capability: "cancel".into(),
                grant: "grant".into(),
                subscriptions: HashMap::new(),
                replay: VecDeque::new(),
                replay_bytes: 0,
                next_sequence: 1,
                phase: GuiChatPhase::Waiting,
                terminal: None,
                effects: HashMap::new(),
                next_effect_id: 1,
                effect_admission: Arc::new(Mutex::new(())),
                effect_changed: Arc::new(Notify::new()),
                owner_registry: Arc::new(StdMutex::new(OwnerRegistry {
                    closed: false,
                    cancellations: Vec::new(),
                })),
                staged: Vec::new(),
                ephemeral: None,
            },
        );
        (runtime, turn_id, completion, home)
    }

    async fn fixture_gate(runtime: &DaemonGuiChatRuntime, turn_id: Uuid) -> RuntimeEffectGate {
        let (effect_admission, effect_changed, owner_registry) = {
            let state = runtime.state.lock().await;
            let turn = state.turns.get(&turn_id).expect("fixture turn");
            (
                turn.effect_admission.clone(),
                turn.effect_changed.clone(),
                turn.owner_registry.clone(),
            )
        };
        RuntimeEffectGate {
            runtime: runtime.clone(),
            turn_id,
            effect_admission,
            effect_changed,
            owner_registry,
        }
    }

    fn lifecycle_phases_from_real_wal(segment: &std::path::Path) -> Vec<String> {
        let bytes = std::fs::read(segment).expect("read real fixture WAL");
        let header = crate::wal::segment_header::parse_segment_header(&bytes)
            .expect("parse real fixture WAL header");
        let mut cursor = &bytes[header.header_len()..];
        let mut phases = Vec::new();
        while !cursor.is_empty() {
            let frame = crate::wal::frame::decode_frame(cursor)
                .expect("decode complete real fixture WAL frame");
            let frame_len = frame.header.total_len as usize;
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::GuiChatLifecycle as u8
            {
                let row: serde_json::Value = serde_json::from_slice(frame.payload)
                    .expect("decode GUI lifecycle WAL payload");
                if let Some(phase) = row.get("phase").and_then(serde_json::Value::as_str) {
                    phases.push(phase.to_owned());
                }
            }
            cursor = &cursor[frame_len..];
        }
        phases
    }

    #[tokio::test]
    async fn started_ack_failure_from_aborted_real_writer_closes_runtime_gate() {
        let (runtime, turn_id, completion, _home) = runtime_with_handshake_turn().await;
        let (admission, changed) = {
            let state = runtime.state.lock().await;
            let turn = state.turns.get(&turn_id).expect("fixture turn");
            (turn.effect_admission.clone(), turn.effect_changed.clone())
        };
        let owner_registry = {
            let state = runtime.state.lock().await;
            state
                .turns
                .get(&turn_id)
                .expect("fixture turn")
                .owner_registry
                .clone()
        };
        let gate = RuntimeEffectGate {
            runtime: runtime.clone(),
            turn_id,
            effect_admission: admission,
            effect_changed: changed,
            owner_registry,
        };
        let intent_binding = "a".repeat(64);
        let reservation = crate::providers::ChatTurnEffectGate::intent(
            &gate,
            crate::providers::ChatTurnEffectKind::Provider {
                call_scope: "w41-fixture",
                streaming: false,
            },
            &intent_binding,
        )
        .await
        .expect("durable intent before writer abort");
        let lease = reservation
            .begin_start()
            .await
            .expect("enter real runtime handshake");
        completion.abort_handle().abort();
        let _ = completion
            .wait_bounded(std::time::Duration::from_secs(1))
            .await;
        assert!(
            lease.started().await.is_err(),
            "Started requires the real WAL ACK"
        );
        let state = runtime.state.lock().await;
        let turn = state.turns.get(&turn_id).expect("fixture turn remains");
        assert!(matches!(
            turn.effects.get(&1).map(|effect| effect.phase),
            Some(EffectPhase::Indeterminate)
        ));
        assert!(turn.cancellation.check_open("assert closed").is_err());
        drop(state);
        let later_binding = "b".repeat(64);
        assert!(
            crate::providers::ChatTurnEffectGate::intent(
                &gate,
                crate::providers::ChatTurnEffectKind::McpToolInvoke,
                &later_binding,
            )
            .await
            .is_err(),
            "Indeterminate must refuse a later start"
        );
    }

    #[tokio::test]
    async fn post_intent_live_consent_rejection_is_durably_aborted_before_any_lease() {
        let (runtime, turn_id, completion, home) = runtime_with_handshake_turn().await;
        let gate = fixture_gate(&runtime, turn_id).await;
        let reservation = gate
            .intent(
                crate::providers::ChatTurnEffectKind::Provider {
                    call_scope: "w41-post-intent-live-consent",
                    streaming: false,
                },
                &"a".repeat(64),
            )
            .await
            .expect("real fixture WAL acknowledges Intent before a live-consent change");

        let error = reservation
            .with_start_authority(Arc::new(PostIntentConsentRevoked))
            .begin_start()
            .await
            .err()
            .expect("a revoked post-Intent authority must not issue a transport lease");
        assert!(error.to_string().contains("live consent"));
        let state = runtime.state.lock().await;
        assert!(matches!(
            state
                .turns
                .get(&turn_id)
                .and_then(|turn| turn.effects.get(&1))
                .map(|effect| effect.phase),
            Some(EffectPhase::Aborted)
        ));
        drop(state);

        let phases = lifecycle_phases_from_real_wal(&home.path().join("wal").join("000001.wal"));
        assert_eq!(
            phases,
            vec!["intent".to_owned(), "aborted".to_owned()],
            "the rejected start has a paired, ordered WAL terminal"
        );

        drop(gate);
        tokio::time::timeout(Duration::from_secs(1), runtime.close_and_drain())
            .await
            .expect("fixture runtime drains after a known pre-start refusal");
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("fixture writer closes after aborted live-consent start");
    }

    #[tokio::test]
    async fn gui_cancel_after_real_intent_before_start_does_not_spend_allow_once() {
        let (runtime, turn_id, completion, home) = runtime_with_handshake_turn().await;
        let gate = fixture_gate(&runtime, turn_id).await;
        let route = crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::OpenaiApi,
            Some("https://api.openai.com"),
        );
        let mut ephemeral = crate::consent::EphemeralConsent::default();
        ephemeral
            .allow_route(&route)
            .expect("exact GUI one-shot route");
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        )
        .with_usage_home(home.path().to_path_buf())
        .with_ephemeral_consent(ephemeral);
        let reservation = gate
            .intent(
                crate::providers::ChatTurnEffectKind::Provider {
                    call_scope: "w41-gui-cancel-before-start",
                    streaming: false,
                },
                &"a".repeat(64),
            )
            .await
            .expect("real GUI Intent WAL ACK")
            .with_start_authority(crate::providers::test_live_consent_start_authority(
                authorizer.clone(),
                route.clone(),
            ));
        let cancel_request = {
            let state = runtime.state.lock().await;
            let turn = state.turns.get(&turn_id).expect("fixture turn");
            GuiChatCancelRequest {
                schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                expected_boot_id: "fixture-boot".into(),
                turn_id: GuiChatTurnId(turn_id),
                session_id: turn.session.clone(),
                cancel_capability: GuiChatOpaqueCapability(turn.cancel_capability.clone()),
            }
        };
        runtime
            .cancel(cancel_request)
            .await
            .expect("cancel commits paired Aborted before start");
        assert!(
            reservation.begin_start().await.is_err(),
            "closed GUI admission rejects before the private callback"
        );
        authorizer
            .ensure_live_consent(Some(&route))
            .expect("GUI cancellation cannot consume AllowOnce before begin_start");
        assert!(authorizer.ensure_live_consent(Some(&route)).is_err());

        drop(gate);
        tokio::time::timeout(Duration::from_secs(1), runtime.close_and_drain())
            .await
            .expect("cancelled fixture runtime drains");
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("fixture writer closes after GUI cancellation");
    }

    #[tokio::test]
    async fn composed_openai_complete_rechecks_blocking_outbox_after_real_intent_before_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("loopback address");
        let (runtime, turn_id, completion, home) = runtime_with_handshake_turn().await;
        let pause = Arc::new(PausedIntentGate {
            inner: fixture_gate(&runtime, turn_id).await,
            intent_acked: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        });
        let route = crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::OpenaiApi,
            Some(&format!("http://{address}")),
        );
        let mut ephemeral = crate::consent::EphemeralConsent::default();
        ephemeral.allow_route(&route).expect("exact route");
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        )
        .with_usage_home(home.path().to_path_buf())
        .with_ephemeral_consent(ephemeral)
        .with_turn_effect_gate(Some(pause.clone()));
        let adapter = crate::providers::openai_api::OpenAiAdapter::new_openai(
            format!("http://{address}"),
            crate::secret::SecretString::from("sk-test"),
            "model".into(),
        )
        .expect("loopback adapter");
        let intent_acked = pause.intent_acked.notified();
        let mut call = tokio::spawn(async move {
            adapter
                .complete_authorized(
                    crate::providers::Request {
                        prompt: "complete block".into(),
                        ..Default::default()
                    },
                    &authorizer,
                    "w41-complete-post-intent-outbox",
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), intent_acked)
            .await
            .expect("real Intent ACK reached pause");
        let update =
            crate::consent::prepare_grant_routes(home.path(), std::slice::from_ref(&route))
                .expect("prepare outbox");
        let pending = crate::cli::consent_outbox::begin(
            home.path(),
            &update,
            crate::cli::consent_outbox::ConsentMutationAction::Grant,
            crate::cli::consent_outbox::ConsentMutationSource::Gui,
            vec![format!("http://{address}")],
            true,
        )
        .await
        .expect("block exact route after Intent");
        pause.release.notify_one();
        let call_status = match tokio::time::timeout(Duration::from_secs(1), &mut call).await {
            Ok(Ok(result)) => Ok(result.is_err()),
            Ok(Err(error)) => Err(format!("complete task join failed: {error}")),
            Err(_) => {
                call.abort();
                let _ = call.await;
                Err("complete task did not settle after the retained release signal".into())
            }
        };
        let no_tcp_accept = tokio::time::timeout(Duration::from_millis(100), async {
            let _ = listener.accept().await;
        })
        .await
        .is_err();
        let state = runtime.state.lock().await;
        assert!(matches!(
            state
                .turns
                .get(&turn_id)
                .and_then(|turn| turn.effects.get(&1))
                .map(|effect| effect.phase),
            Some(EffectPhase::Aborted)
        ));
        drop(state);
        drop(pending);
        std::fs::remove_file(crate::cli::consent_outbox::journal_path(home.path()))
            .expect("remove fixture journal");
        drop(pause);
        runtime.close_and_drain().await;
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("writer drains");
        assert!(
            call_status.expect("complete task settles"),
            "outbox blocks before response-head TCP"
        );
        assert!(
            no_tcp_accept,
            "blocked complete does not reach loopback listener"
        );
    }

    #[tokio::test]
    async fn composed_openai_stream_rechecks_blocking_outbox_after_real_intent_before_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("loopback address");
        let (runtime, turn_id, completion, home) = runtime_with_handshake_turn().await;
        let pause = Arc::new(PausedIntentGate {
            inner: fixture_gate(&runtime, turn_id).await,
            intent_acked: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        });
        let route = crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::OpenaiApi,
            Some(&format!("http://{address}")),
        );
        let mut ephemeral = crate::consent::EphemeralConsent::default();
        ephemeral.allow_route(&route).expect("exact route");
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        )
        .with_usage_home(home.path().to_path_buf())
        .with_ephemeral_consent(ephemeral)
        .with_turn_effect_gate(Some(pause.clone()));
        let adapter = crate::providers::openai_api::OpenAiAdapter::new_openai(
            format!("http://{address}"),
            crate::secret::SecretString::from("sk-test"),
            "model".into(),
        )
        .expect("loopback adapter");
        let intent_acked = pause.intent_acked.notified();
        let mut call = tokio::spawn(async move {
            adapter
                .stream_authorized(
                    crate::providers::Request {
                        prompt: "stream block".into(),
                        ..Default::default()
                    },
                    &authorizer,
                    "w41-stream-post-intent-outbox",
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), intent_acked)
            .await
            .expect("real stream Intent ACK reached pause");
        let update =
            crate::consent::prepare_grant_routes(home.path(), std::slice::from_ref(&route))
                .expect("prepare outbox");
        let pending = crate::cli::consent_outbox::begin(
            home.path(),
            &update,
            crate::cli::consent_outbox::ConsentMutationAction::Grant,
            crate::cli::consent_outbox::ConsentMutationSource::Gui,
            vec![format!("http://{address}")],
            true,
        )
        .await
        .expect("block exact route after Intent");
        pause.release.notify_one();
        let call_status = match tokio::time::timeout(Duration::from_secs(1), &mut call).await {
            Ok(Ok(result)) => Ok(result.is_err()),
            Ok(Err(error)) => Err(format!("stream task join failed: {error}")),
            Err(_) => {
                call.abort();
                let _ = call.await;
                Err("stream task did not settle after the retained release signal".into())
            }
        };
        let no_tcp_accept = tokio::time::timeout(Duration::from_millis(100), async {
            let _ = listener.accept().await;
        })
        .await
        .is_err();
        let state = runtime.state.lock().await;
        assert!(matches!(
            state
                .turns
                .get(&turn_id)
                .and_then(|turn| turn.effects.get(&1))
                .map(|effect| effect.phase),
            Some(EffectPhase::Aborted)
        ));
        drop(state);
        drop(pending);
        std::fs::remove_file(crate::cli::consent_outbox::journal_path(home.path()))
            .expect("remove fixture journal");
        drop(pause);
        runtime.close_and_drain().await;
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("writer drains");
        assert!(
            call_status.expect("stream task settles"),
            "outbox blocks before stream response-head TCP"
        );
        assert!(
            no_tcp_accept,
            "blocked stream does not reach loopback listener"
        );
    }

    #[tokio::test]
    async fn cancel_waits_for_held_real_handshake_terminal_ack_before_accepting() {
        let (runtime, turn_id, completion, home) = runtime_with_handshake_turn().await;
        let gate = fixture_gate(&runtime, turn_id).await;
        let reservation = gate
            .intent(
                crate::providers::ChatTurnEffectKind::Provider {
                    call_scope: "w41-cancel-held-handshake",
                    streaming: false,
                },
                &"a".repeat(64),
            )
            .await
            .expect("durably reserve real held handshake");
        let lease = reservation
            .begin_start()
            .await
            .expect("enter real held handshake");

        let cancel_request = {
            let state = runtime.state.lock().await;
            let turn = state.turns.get(&turn_id).expect("fixture turn remains");
            GuiChatCancelRequest {
                schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
                expected_boot_id: "fixture-boot".into(),
                turn_id: GuiChatTurnId(turn_id),
                session_id: turn.session.clone(),
                cancel_capability: GuiChatOpaqueCapability(turn.cancel_capability.clone()),
            }
        };
        let cancelling_runtime = runtime.clone();
        let mut cancelling =
            tokio::spawn(async move { cancelling_runtime.cancel(cancel_request).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let state = runtime.state.lock().await;
                let closed = state
                    .turns
                    .get(&turn_id)
                    .expect("fixture turn remains")
                    .cancellation
                    .check_open("observe cancel admission closure")
                    .is_err();
                drop(state);
                if closed {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancel closes start admission within a bounded wait");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut cancelling)
                .await
                .is_err(),
            "cancel must not report Accepted while the real handshake has no terminal ACK"
        );
        lease
            .aborted_proven_pre_start()
            .await
            .expect("durably prove no actual effect began");
        let response = tokio::time::timeout(Duration::from_secs(1), &mut cancelling)
            .await
            .expect("cancel returns after the terminal handshake ACK")
            .expect("join cancelling task")
            .expect("cancel request succeeds");
        assert_eq!(response.outcome, GuiChatCancelOutcome::Accepted);
        assert!(
            gate.intent(
                crate::providers::ChatTurnEffectKind::McpToolInvoke,
                &"b".repeat(64),
            )
            .await
            .is_err(),
            "cancellation refuses every later effect after the held handshake settles"
        );

        let phases = lifecycle_phases_from_real_wal(&home.path().join("wal").join("000001.wal"));
        let terminal = phases
            .iter()
            .position(|phase| phase == "aborted")
            .expect("real WAL contains the proven-pre-start terminal ACK");
        let cancel = phases
            .iter()
            .position(|phase| phase == "cancel_requested")
            .expect("real WAL contains the accepted cancellation ACK");
        assert!(
            terminal < cancel,
            "the real WAL terminal record precedes CancelRequested: {phases:?}"
        );

        drop(gate);
        tokio::time::timeout(Duration::from_secs(1), runtime.close_and_drain())
            .await
            .expect("bounded fixture cleanup drains the runtime");
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("real fixture writer closes after runtime cleanup");
    }

    #[tokio::test]
    async fn registered_blocked_worker_is_cancelled_and_joined_before_w39_drain() {
        let (runtime, turn_id, completion, _home) = runtime_with_handshake_turn().await;
        let gate = fixture_gate(&runtime, turn_id).await;
        let start_permission = Arc::new(AtomicBool::new(false));
        let cancellation_seen = Arc::new(AtomicBool::new(false));
        let actual_io_started = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::new(Notify::new());
        let worker_release = Arc::new(Notify::new());
        let entered_wait = worker_entered.notified();

        let worker = {
            let start_permission = Arc::clone(&start_permission);
            let cancellation_seen = Arc::clone(&cancellation_seen);
            let actual_io_started = Arc::clone(&actual_io_started);
            let worker_exited = Arc::clone(&worker_exited);
            let worker_entered = Arc::clone(&worker_entered);
            let worker_release = Arc::clone(&worker_release);
            tokio::spawn(async move {
                worker_entered.notify_waiters();
                loop {
                    if cancellation_seen.load(Ordering::Acquire) {
                        worker_exited.store(true, Ordering::Release);
                        return;
                    }
                    if start_permission.load(Ordering::Acquire) {
                        actual_io_started.store(true, Ordering::Release);
                        worker_exited.store(true, Ordering::Release);
                        return;
                    }
                    worker_release.notified().await;
                }
            })
        };
        tokio::time::timeout(Duration::from_secs(1), entered_wait)
            .await
            .expect("blocked worker enters before owner registration");
        assert!(
            !actual_io_started.load(Ordering::Acquire),
            "a worker blocked before start permission performs no actual I/O"
        );

        let cancellation = {
            let cancellation_seen = Arc::clone(&cancellation_seen);
            let worker_release = Arc::clone(&worker_release);
            EffectOwnerCancellation::new(move || {
                cancellation_seen.store(true, Ordering::Release);
                worker_release.notify_waiters();
            })
        };
        assert!(
            matches!(
                gate.register_owner(TurnEffectOwner::new(
                    Box::pin(async move {
                        worker
                            .await
                            .expect("blocked worker joins through daemon owner registry");
                    }),
                    cancellation,
                )),
                crate::providers::EffectOwnerRegistration::Registered
            ),
            "synchronously register worker drain before its start permission"
        );

        tokio::time::timeout(Duration::from_secs(1), runtime.close_and_drain())
            .await
            .expect("close_and_drain waits for the registered worker before W39 drain");
        assert!(
            cancellation_seen.load(Ordering::Acquire),
            "turn cancellation invokes the registered worker cancellation hook"
        );
        assert!(
            worker_exited.load(Ordering::Acquire),
            "registered worker exits before close_and_drain reaches the W39 WAL drain"
        );
        assert!(
            !actual_io_started.load(Ordering::Acquire),
            "cancellation refuses the still-blocked worker before actual I/O"
        );

        drop(gate);
        drop(runtime);
        completion
            .wait_bounded(Duration::from_secs(1))
            .await
            .expect("real writer closes after the joined worker and W39 drain");
    }
}
