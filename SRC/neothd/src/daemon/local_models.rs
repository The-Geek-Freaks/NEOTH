//! Daemon-owned, loopback-only Ollama inventory and mutation controller.
//!
//! This module deliberately owns HTTP mutations instead of borrowing the
//! background-job registry: an Ollama pull is a streaming HTTP request whose
//! cancellation and uncertain remote outcome must remain attached to one
//! controller instance.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

const SCHEMA_VERSION: u32 = 1;
const STATUS_FILE: &str = "local-models-v1.json";
const MAX_STATE_BYTES: usize = 256 * 1024;
const MAX_MODELS: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_NDJSON_FRAME: usize = 64 * 1024;
const MAX_TERMINAL_RECEIPTS: usize = 16;
const PROBE_CADENCE: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PULL_OVERALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const PULL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const PROBE_PROMPT: &str = "Reply with OK.";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalModelEndpoint {
    pub(crate) base_url: String,
    pub(crate) configured_model: Option<String>,
}

impl LocalModelEndpoint {
    /// Resolves the only endpoint source W185 accepts. Lifecycle code supplies
    /// the active FreedomConfig fields; remote origins remain representable but
    /// are never contacted by this controller.
    pub(crate) fn from_provider_config(
        provider_endpoint: Option<String>,
        provider_model: Option<String>,
    ) -> Self {
        Self {
            base_url: provider_endpoint
                .unwrap_or_else(|| crate::providers::ollama_api::DEFAULT_BASE_URL.to_owned()),
            configured_model: provider_model,
        }
    }

    fn parsed_loopback_url(&self) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(self.base_url.trim_end_matches('/'))
            .context("parse configured Ollama endpoint")?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "Ollama endpoint must use http or https"
        );
        anyhow::ensure!(
            crate::providers::http_client::url_has_loopback_host(&url),
            "Ollama endpoint is not loopback"
        );
        Ok(url)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelsSnapshot {
    pub(crate) schema_version: u32,
    pub(crate) observed_at_unix_ms: u64,
    pub(crate) endpoint: LocalEndpointStatus,
    pub(crate) host_resources: LocalHostResources,
    pub(crate) models: Vec<LocalModelRow>,
    pub(crate) active_operation: Option<LocalModelOperation>,
    pub(crate) last_terminal_operation: Option<LocalModelTerminalReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum LocalEndpointStatus {
    Unavailable { detail: String },
    UnsupportedRemoteEndpoint { redacted_origin: String },
    Reachable { detail: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct LocalHostResources {
    /// Presentation-only join populated by the lifecycle owner when available.
    pub(crate) ram_bytes: Option<u64>,
    pub(crate) vram_bytes: Option<u64>,
    pub(crate) gpu_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelRow {
    pub(crate) model: String,
    pub(crate) digest: String,
    pub(crate) size_bytes: u64,
    pub(crate) loaded: Option<LoadedModelUse>,
    pub(crate) readiness: LocalModelReadiness,
    pub(crate) last_error: Option<LocalModelError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LoadedModelUse {
    pub(crate) model: String,
    pub(crate) name: Option<String>,
    pub(crate) digest: String,
    pub(crate) size_bytes: u64,
    pub(crate) size_vram_bytes: Option<u64>,
    pub(crate) expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum LocalModelReadiness {
    Unavailable,
    Installed,
    Probing,
    Ready {
        verified_at_unix_ms: u64,
    },
    ReachableButUnready {
        reason: LocalModelUnreadyReason,
    },
    Downloading {
        operation_id: String,
        completed: Option<u64>,
        total: Option<u64>,
    },
    Updating {
        operation_id: String,
        completed: Option<u64>,
        total: Option<u64>,
    },
    Pruning {
        operation_id: String,
    },
    Failed {
        operation_id: String,
        code: LocalModelErrorCode,
    },
    CancelRequested {
        operation_id: String,
    },
    InterruptedUnknown {
        operation_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalModelUnreadyReason {
    ProbeFailed,
    MissingFreshLoadedDigest,
    ResponseModelMismatch,
    NotSelected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalModelErrorCode {
    InvalidRequest,
    EndpointUnavailable,
    Protocol,
    Transport,
    RemoteRejected,
    Cancelled,
    InterruptedUnknown,
    Conflict,
    Persistence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelError {
    pub(crate) code: LocalModelErrorCode,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(crate) enum LocalModelAction {
    Pull { model: String },
    Update { model: String },
    Prune { model: String },
    Retry { terminal_operation_id: String },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalModelActionKind {
    Pull,
    Update,
    Prune,
    Retry,
}

impl LocalModelAction {
    fn kind(&self) -> LocalModelActionKind {
        match self {
            Self::Pull { .. } => LocalModelActionKind::Pull,
            Self::Update { .. } => LocalModelActionKind::Update,
            Self::Prune { .. } => LocalModelActionKind::Prune,
            Self::Retry { .. } => LocalModelActionKind::Retry,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelOperation {
    pub(crate) operation_id: String,
    pub(crate) action: LocalModelActionKind,
    pub(crate) model: String,
    pub(crate) started_at_unix_ms: u64,
    pub(crate) progress: Option<LocalModelProgress>,
    pub(crate) cancellation_requested: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelProgress {
    pub(crate) status: String,
    pub(crate) completed: Option<u64>,
    pub(crate) total: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelTerminalReceipt {
    pub(crate) operation_id: String,
    pub(crate) action: LocalModelActionKind,
    pub(crate) model: String,
    pub(crate) started_at_unix_ms: u64,
    pub(crate) finished_at_unix_ms: u64,
    pub(crate) outcome: LocalModelTerminalOutcome,
    pub(crate) old_digest: Option<String>,
    pub(crate) new_digest: Option<String>,
    pub(crate) error: Option<LocalModelError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalModelTerminalOutcome {
    Completed,
    Failed,
    InterruptedUnknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalModelActionAck {
    pub(crate) schema_version: u32,
    pub(crate) ok: bool,
    pub(crate) action: LocalModelActionKind,
    pub(crate) operation_id: Option<String>,
    pub(crate) error: Option<LocalModelError>,
    pub(crate) snapshot: LocalModelsSnapshot,
}

struct PersistedState {
    root: crate::skills::store::BoundDirectory,
    path: PathBuf,
}
struct Active {
    operation: LocalModelOperation,
    cancelled: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
    terminal_committed: bool,
}

struct State {
    snapshot: LocalModelsSnapshot,
    active: Option<Active>,
    receipts: Vec<LocalModelTerminalReceipt>,
    last_probe_at: u64,
    persistence_fault: Option<String>,
    revision: u64,
}

struct Inner {
    endpoint: LocalModelEndpoint,
    http: Option<reqwest::Client>,
    pull_http: Option<reqwest::Client>,
    store: PersistedState,
    state: Mutex<State>,
    operation_gate: Arc<Semaphore>,
    persist_lock: StdMutex<()>,
    #[cfg(test)]
    fail_critical_persist: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct LocalModelController {
    inner: Arc<Inner>,
}

impl LocalModelController {
    pub(crate) fn new(home: PathBuf, endpoint: LocalModelEndpoint) -> Result<Self> {
        let root_path = home.join("local-models");
        let root =
            crate::skills::store::open_bound_directory(&root_path, true, "local model state")?
                .context("open local model state root")?;
        let http = endpoint
            .parsed_loopback_url()
            .ok()
            .map(|_| {
                reqwest::Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
            })
            .transpose()?;
        // Pulls are allowed a bounded transfer window, but each received frame
        // is subject to PULL_IDLE_TIMEOUT below so a silent peer cannot hold a
        // daemon mutation slot indefinitely.
        let pull_http = endpoint
            .parsed_loopback_url()
            .ok()
            .map(|_| {
                reqwest::Client::builder()
                    .timeout(PULL_OVERALL_TIMEOUT)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
            })
            .transpose()?;
        let endpoint_status = match endpoint.parsed_loopback_url() {
            Ok(_) => LocalEndpointStatus::Unavailable {
                detail: "not yet observed".to_owned(),
            },
            Err(_) => LocalEndpointStatus::UnsupportedRemoteEndpoint {
                redacted_origin: redact_origin(&endpoint.base_url),
            },
        };
        let snapshot = LocalModelsSnapshot {
            schema_version: SCHEMA_VERSION,
            observed_at_unix_ms: now_ms(),
            endpoint: endpoint_status,
            host_resources: LocalHostResources::default(),
            models: Vec::new(),
            active_operation: None,
            last_terminal_operation: None,
        };
        let controller = Self {
            inner: Arc::new(Inner {
                endpoint,
                http,
                pull_http,
                store: PersistedState {
                    root,
                    path: root_path.join(STATUS_FILE),
                },
                state: Mutex::new(State {
                    snapshot,
                    active: None,
                    receipts: Vec::new(),
                    last_probe_at: 0,
                    persistence_fault: None,
                    revision: 0,
                }),
                operation_gate: Arc::new(Semaphore::new(1)),
                persist_lock: StdMutex::new(()),
                #[cfg(test)]
                fail_critical_persist: AtomicBool::new(false),
            }),
        };
        controller.reconcile_restart()?;
        Ok(controller)
    }

    pub(crate) async fn status(&self) -> LocalModelsSnapshot {
        self.reap_finished_terminal().await;
        self.inner.state.lock().await.snapshot.clone()
    }

    /// Inventory refresh is bounded and never probes every installed model.
    pub(crate) async fn refresh(&self) -> LocalModelsSnapshot {
        self.reap_finished_terminal().await;
        let Some(http) = &self.inner.http else {
            return self.status().await;
        };
        // The permit is owned by this future. Dropping an aborted refresh also
        // drops it, so a cancelled probe cannot permanently block mutations.
        let Ok(_permit) = Arc::clone(&self.inner.operation_gate).try_acquire_owned() else {
            return self.status().await;
        };
        {
            let state = self.inner.state.lock().await;
            if state.active.is_some() || state.persistence_fault.is_some() {
                return state.snapshot.clone();
            }
        }
        match inventory(http, &self.inner.endpoint).await {
            Ok((tags, ps)) => {
                let mut state = self.inner.state.lock().await;
                state.snapshot.endpoint = LocalEndpointStatus::Reachable {
                    detail: "fresh tags and ps".to_owned(),
                };
                state.snapshot.models = join_inventory(tags, ps);
                if let Some(receipt) = state.snapshot.last_terminal_operation.clone()
                    && matches!(
                        receipt.outcome,
                        LocalModelTerminalOutcome::InterruptedUnknown
                    )
                {
                    // Inventory proves current installation state, but not the
                    // outcome of an interrupted remote mutation. Preserve the
                    // durable uncertainty until a later terminal receipt.
                    apply_terminal(&mut state.snapshot.models, &receipt);
                }
                state.snapshot.observed_at_unix_ms = now_ms();
                state.revision = state.revision.wrapping_add(1);
                let should_probe = state
                    .last_probe_at
                    .saturating_add(PROBE_CADENCE.as_millis() as u64)
                    <= now_ms();
                let candidate = self.inner.endpoint.configured_model.clone();
                drop(state);
                if should_probe && let Some(model) = candidate {
                    self.probe_candidate(&model).await;
                }
            }
            Err(error) => {
                let mut state = self.inner.state.lock().await;
                state.snapshot.endpoint = LocalEndpointStatus::Unavailable {
                    detail: bounded(&error.to_string()),
                };
                state.snapshot.models.clear();
                state.snapshot.observed_at_unix_ms = now_ms();
                state.revision = state.revision.wrapping_add(1);
            }
        }
        self.persist_current().await;
        self.status().await
    }

    async fn probe_candidate(&self, model: &str) {
        let Some(http) = &self.inner.http else {
            return;
        };
        {
            let mut state = self.inner.state.lock().await;
            state.last_probe_at = now_ms();
            for row in &mut state.snapshot.models {
                if row.model == model {
                    row.readiness = LocalModelReadiness::Probing;
                }
            }
            state.revision = state.revision.wrapping_add(1);
        }
        let outcome = probe_ready(http, &self.inner.endpoint, model).await;
        let mut state = self.inner.state.lock().await;
        for row in &mut state.snapshot.models {
            if row.model == model {
                row.readiness = match &outcome {
                    Ok(loaded) if loaded.digest == row.digest => {
                        row.loaded = Some(loaded.clone());
                        LocalModelReadiness::Ready {
                            verified_at_unix_ms: now_ms(),
                        }
                    }
                    Ok(_) => LocalModelReadiness::ReachableButUnready {
                        reason: LocalModelUnreadyReason::MissingFreshLoadedDigest,
                    },
                    Err(ProbeFailure::ResponseModelMismatch) => {
                        LocalModelReadiness::ReachableButUnready {
                            reason: LocalModelUnreadyReason::ResponseModelMismatch,
                        }
                    }
                    Err(_) => LocalModelReadiness::ReachableButUnready {
                        reason: LocalModelUnreadyReason::ProbeFailed,
                    },
                };
            }
        }
        state.snapshot.observed_at_unix_ms = now_ms();
        state.revision = state.revision.wrapping_add(1);
        drop(state);
        self.persist_current().await;
    }

    pub(crate) async fn start(&self, action: LocalModelAction) -> LocalModelActionAck {
        let requested_kind = action.kind();
        let resolved = match self.resolve_action(action).await {
            Ok(value) => value,
            Err(error) => return self.ack_error(requested_kind, error).await,
        };
        let (kind, model) = resolved;
        if validate_model(&model).is_err() {
            return self
                .ack_error(kind, anyhow::anyhow!("model selector is invalid"))
                .await;
        }
        self.reap_finished_terminal().await;
        let permit = match Arc::clone(&self.inner.operation_gate).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return self
                    .conflict_ack(kind, "local-model observation or operation is in progress")
                    .await;
            }
        };
        let mut state = self.inner.state.lock().await;
        if let Some(detail) = &state.persistence_fault {
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action: kind,
                operation_id: None,
                error: Some(err(LocalModelErrorCode::Persistence, detail)),
                snapshot: state.snapshot.clone(),
            };
        }
        if let Some(active) = &state.active {
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action: kind,
                operation_id: Some(active.operation.operation_id.clone()),
                error: Some(err(
                    LocalModelErrorCode::Conflict,
                    "another local-model operation is active",
                )),
                snapshot: state.snapshot.clone(),
            };
        }
        let operation = LocalModelOperation {
            operation_id: uuid::Uuid::now_v7().to_string(),
            action: kind,
            model: model.clone(),
            started_at_unix_ms: now_ms(),
            progress: None,
            cancellation_requested: false,
        };
        suppress_ready_for_operation(&mut state.snapshot.models, &operation);
        state.snapshot.active_operation = Some(operation.clone());
        state.snapshot.observed_at_unix_ms = now_ms();
        let cancelled = Arc::new(AtomicBool::new(false));
        // Publish a parked task together with its active intent. Cancellation
        // can therefore always reap a real owned handle, while the one-shot
        // prevents any HTTP effect until durable admission succeeds.
        let (start_tx, start_rx) = oneshot::channel();
        let worker = self.clone();
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_operation = operation.clone();
        let task = tokio::spawn(async move {
            worker
                .run_operation(worker_operation, worker_cancelled, permit, start_rx)
                .await;
        });
        state.active = Some(Active {
            operation: operation.clone(),
            cancelled: Arc::clone(&cancelled),
            task: Some(task),
            terminal_committed: false,
        });
        state.revision = state.revision.wrapping_add(1);
        // Hold the state lock through the durable intent write. No cancel or
        // terminal write can replace it between snapshot capture and persist.
        if let Err(error) = self.persist_snapshot_critical(&state.snapshot) {
            if let Some(task) = state
                .active
                .as_mut()
                .and_then(|active| active.task.as_mut())
            {
                task.abort();
                let _ = task.await;
            }
            state.active = None;
            state.snapshot.active_operation = None;
            state.snapshot.observed_at_unix_ms = now_ms();
            state.persistence_fault = Some(bounded(&error.to_string()));
            state.revision = state.revision.wrapping_add(1);
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action: kind,
                operation_id: None,
                error: Some(err(LocalModelErrorCode::Persistence, error.to_string())),
                snapshot: state.snapshot.clone(),
            };
        }
        let snapshot = state.snapshot.clone();
        let _ = start_tx.send(());
        LocalModelActionAck {
            schema_version: SCHEMA_VERSION,
            ok: true,
            action: kind,
            operation_id: Some(operation.operation_id),
            error: None,
            snapshot,
        }
    }

    pub(crate) async fn cancel(&self, operation_id: &str) -> LocalModelActionAck {
        let mut state = self.inner.state.lock().await;
        let Some(active) = state.active.as_mut() else {
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action: LocalModelActionKind::Pull,
                operation_id: None,
                error: Some(err(
                    LocalModelErrorCode::Conflict,
                    "no active local-model operation",
                )),
                snapshot: state.snapshot.clone(),
            };
        };
        if active.operation.operation_id != operation_id {
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action: active.operation.action,
                operation_id: Some(active.operation.operation_id.clone()),
                error: Some(err(
                    LocalModelErrorCode::Conflict,
                    "operation id is not active",
                )),
                snapshot: state.snapshot.clone(),
            };
        }
        let operation = active.operation.clone();
        let action = operation.action;
        let terminal_committed = active.terminal_committed;
        active.cancelled.store(true, Ordering::Release);
        active.operation.cancellation_requested = true;
        // Keep the handle in Active while awaiting it. Concurrent cancel and
        // shutdown serialize on state; dropping this future cannot detach it.
        // Abort makes the join independent of any state lock the worker needs.
        if let Some(task) = active.task.as_mut() {
            task.abort();
            let _ = task.await;
        }
        active.task = None;
        if terminal_committed {
            state.active = None;
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action,
                operation_id: Some(operation_id.to_owned()),
                error: Some(err(
                    LocalModelErrorCode::Conflict,
                    "operation is already terminal; reconciliation was stopped",
                )),
                snapshot: state.snapshot.clone(),
            };
        }
        let receipt = terminal_receipt(
            &operation,
            LocalModelTerminalOutcome::InterruptedUnknown,
            None,
            None,
            Some(err(
                LocalModelErrorCode::InterruptedUnknown,
                "HTTP request aborted; remote outcome is uncertain",
            )),
        );
        if let Err(error) = self.finish_terminal_locked(&mut state, operation_id, receipt) {
            return LocalModelActionAck {
                schema_version: SCHEMA_VERSION,
                ok: false,
                action,
                operation_id: Some(operation_id.to_owned()),
                error: Some(err(LocalModelErrorCode::Persistence, error.to_string())),
                snapshot: state.snapshot.clone(),
            };
        }
        state.active = None;
        LocalModelActionAck {
            schema_version: SCHEMA_VERSION,
            ok: true,
            action,
            operation_id: Some(operation_id.to_owned()),
            error: None,
            snapshot: state.snapshot.clone(),
        }
    }

    /// Lifecycle owner closes IPC admission before draining the controller.
    pub(crate) async fn shutdown(&self) {
        let operation_id = {
            let state = self.inner.state.lock().await;
            state
                .active
                .as_ref()
                .map(|active| active.operation.operation_id.clone())
        };
        if let Some(operation_id) = operation_id {
            let _ = self.cancel(&operation_id).await;
        }
    }
    pub(crate) fn reconcile_restart(&self) -> Result<()> {
        let persisted = load_persisted(&self.inner.store)?;
        let Some(mut saved) = persisted else {
            return Ok(());
        };
        if let Some(active) = saved.active_operation.take() {
            let receipt = LocalModelTerminalReceipt {
                operation_id: active.operation_id.clone(),
                action: active.action,
                model: active.model.clone(),
                started_at_unix_ms: active.started_at_unix_ms,
                finished_at_unix_ms: now_ms(),
                outcome: LocalModelTerminalOutcome::InterruptedUnknown,
                old_digest: None,
                new_digest: None,
                error: Some(err(
                    LocalModelErrorCode::InterruptedUnknown,
                    "daemon restarted while remote outcome was uncertain",
                )),
            };
            apply_terminal(&mut saved.models, &receipt);

            saved.last_terminal_operation = Some(receipt);
        }
        // Persisted observations are diagnostic only. Rebind status to the
        // current configured endpoint and never revive a prior readiness proof.
        saved.schema_version = SCHEMA_VERSION;
        saved.observed_at_unix_ms = now_ms();
        saved.endpoint = match self.inner.endpoint.parsed_loopback_url() {
            Ok(_) => LocalEndpointStatus::Unavailable {
                detail: "awaiting fresh observation after restart".to_owned(),
            },
            Err(_) => LocalEndpointStatus::UnsupportedRemoteEndpoint {
                redacted_origin: redact_origin(&self.inner.endpoint.base_url),
            },
        };
        for row in &mut saved.models {
            row.loaded = None;
            if !matches!(
                row.readiness,
                LocalModelReadiness::InterruptedUnknown { .. }
            ) {
                row.readiness = LocalModelReadiness::Unavailable;
            }
        }
        let snapshot = saved.clone();
        let mut state =
            self.inner.state.try_lock().map_err(|_| {
                anyhow::anyhow!("new local-model controller state unexpectedly busy")
            })?;
        state.receipts = saved.last_terminal_operation.clone().into_iter().collect();
        state.snapshot = saved;
        state.revision = state.revision.wrapping_add(1);
        drop(state);
        persist(&self.inner.store, &snapshot, &self.inner.persist_lock)?;
        Ok(())
    }

    async fn resolve_action(
        &self,
        action: LocalModelAction,
    ) -> Result<(LocalModelActionKind, String)> {
        match action {
            LocalModelAction::Pull { model } => Ok((LocalModelActionKind::Pull, model)),
            LocalModelAction::Update { model } => Ok((LocalModelActionKind::Update, model)),
            LocalModelAction::Prune { model } => Ok((LocalModelActionKind::Prune, model)),
            LocalModelAction::Retry {
                terminal_operation_id,
            } => {
                let state = self.inner.state.lock().await;
                let receipt = state
                    .receipts
                    .iter()
                    .rev()
                    .find(|entry| entry.operation_id == terminal_operation_id)
                    .context("terminal operation receipt not retained")?;
                anyhow::ensure!(
                    matches!(receipt.outcome, LocalModelTerminalOutcome::Failed),
                    "only failed operations can be retried; interrupted remote outcome requires explicit inspection"
                );
                Ok((receipt.action, receipt.model.clone()))
            }
        }
    }

    async fn ack_error(
        &self,
        action: LocalModelActionKind,
        error: anyhow::Error,
    ) -> LocalModelActionAck {
        LocalModelActionAck {
            schema_version: SCHEMA_VERSION,
            ok: false,
            action,
            operation_id: None,
            error: Some(err(classify_error(&error), error.to_string())),
            snapshot: self.status().await,
        }
    }

    async fn conflict_ack(
        &self,
        action: LocalModelActionKind,
        detail: &str,
    ) -> LocalModelActionAck {
        LocalModelActionAck {
            schema_version: SCHEMA_VERSION,
            ok: false,
            action,
            operation_id: None,
            error: Some(err(LocalModelErrorCode::Conflict, detail)),
            snapshot: self.status().await,
        }
    }

    async fn run_operation(
        &self,
        operation: LocalModelOperation,
        cancelled: Arc<AtomicBool>,
        _permit: OwnedSemaphorePermit,
        start: oneshot::Receiver<()>,
    ) {
        if start.await.is_err() {
            return;
        }
        let receipt = match self.execute_operation(&operation, &cancelled).await {
            Ok((old_digest, new_digest)) => terminal_receipt(
                &operation,
                LocalModelTerminalOutcome::Completed,
                old_digest,
                new_digest,
                None,
            ),
            Err(_) if cancelled.load(Ordering::Acquire) => terminal_receipt(
                &operation,
                LocalModelTerminalOutcome::InterruptedUnknown,
                None,
                None,
                Some(err(
                    LocalModelErrorCode::InterruptedUnknown,
                    "cancellation raced an HTTP request; remote outcome is uncertain",
                )),
            ),
            Err(OperationFailure::Uncertain(error)) => terminal_receipt(
                &operation,
                LocalModelTerminalOutcome::InterruptedUnknown,
                None,
                None,
                Some(err(
                    LocalModelErrorCode::InterruptedUnknown,
                    error.to_string(),
                )),
            ),
            Err(OperationFailure::Failed { code, error }) => terminal_receipt(
                &operation,
                LocalModelTerminalOutcome::Failed,
                None,
                None,
                Some(err(code, error.to_string())),
            ),
        };
        if self
            .finish_terminal(&operation.operation_id, receipt)
            .await
            .is_ok()
        {
            self.reconcile_terminal_model(&operation.model).await;
        }
    }

    async fn reap_finished_terminal(&self) {
        let mut state = self.inner.state.lock().await;
        let Some(active) = state.active.as_mut() else {
            return;
        };
        if !active.terminal_committed || !active.task.as_ref().is_some_and(JoinHandle::is_finished)
        {
            return;
        }
        // The finished task stays owned even if the observing future is dropped.
        if let Some(task) = active.task.as_mut() {
            let _ = task.await;
        }
        state.active = None;
    }
    async fn reconcile_terminal_model(&self, model: &str) {
        let Some(http) = &self.inner.http else {
            return;
        };
        let Ok((tags, ps)) = inventory(http, &self.inner.endpoint).await else {
            return;
        };
        {
            let mut state = self.inner.state.lock().await;
            state.snapshot.models = join_inventory(tags, ps);
            state.snapshot.observed_at_unix_ms = now_ms();
            state.revision = state.revision.wrapping_add(1);
        }
        let outcome = probe_ready(http, &self.inner.endpoint, model).await;
        let mut state = self.inner.state.lock().await;
        for row in &mut state.snapshot.models {
            if row.model == model {
                row.readiness = match &outcome {
                    Ok(loaded) if loaded.digest == row.digest => {
                        row.loaded = Some(loaded.clone());
                        LocalModelReadiness::Ready {
                            verified_at_unix_ms: now_ms(),
                        }
                    }
                    Ok(_) => LocalModelReadiness::ReachableButUnready {
                        reason: LocalModelUnreadyReason::MissingFreshLoadedDigest,
                    },
                    Err(ProbeFailure::ResponseModelMismatch) => {
                        LocalModelReadiness::ReachableButUnready {
                            reason: LocalModelUnreadyReason::ResponseModelMismatch,
                        }
                    }
                    Err(_) => LocalModelReadiness::ReachableButUnready {
                        reason: LocalModelUnreadyReason::ProbeFailed,
                    },
                };
            }
        }
        state.snapshot.observed_at_unix_ms = now_ms();
        state.revision = state.revision.wrapping_add(1);
        drop(state);
        self.persist_current().await;
    }

    async fn finish_terminal(
        &self,
        operation_id: &str,
        receipt: LocalModelTerminalReceipt,
    ) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        self.finish_terminal_locked(&mut state, operation_id, receipt)
    }

    fn finish_terminal_locked(
        &self,
        state: &mut State,
        operation_id: &str,
        receipt: LocalModelTerminalReceipt,
    ) -> Result<()> {
        if state
            .active
            .as_ref()
            .is_none_or(|active| active.operation.operation_id != operation_id)
        {
            return Ok(());
        }
        let mut staged = state.snapshot.clone();
        staged.active_operation = None;
        staged.last_terminal_operation = Some(receipt.clone());
        apply_terminal(&mut staged.models, &receipt);
        staged.observed_at_unix_ms = now_ms();
        if let Err(error) = self.persist_snapshot_critical(&staged) {
            state.persistence_fault = Some(bounded(&error.to_string()));
            return Err(error);
        }
        state.receipts.push(receipt);
        if state.receipts.len() > MAX_TERMINAL_RECEIPTS {
            state.receipts.remove(0);
        }
        state.snapshot = staged;
        if let Some(active) = state.active.as_mut() {
            active.terminal_committed = true;
        }
        state.revision = state.revision.wrapping_add(1);
        Ok(())
    }

    async fn execute_operation(
        &self,
        operation: &LocalModelOperation,
        cancelled: &AtomicBool,
    ) -> std::result::Result<(Option<String>, Option<String>), OperationFailure> {
        let http = self
            .inner
            .http
            .as_ref()
            .context("configured endpoint is not loopback")
            .map_err(OperationFailure::preflight)?;
        let pull_http = self
            .inner
            .pull_http
            .as_ref()
            .context("configured endpoint is not loopback")
            .map_err(OperationFailure::preflight)?;
        let (tags, ps) = inventory(http, &self.inner.endpoint)
            .await
            .map_err(OperationFailure::preflight)?;
        let old_digest = tags
            .iter()
            .find(|tag| tag_selector(tag) == operation.model)
            .map(|tag| tag.digest.clone());
        match operation.action {
            LocalModelActionKind::Pull => tokio::time::timeout(
                PULL_OVERALL_TIMEOUT,
                stream_pull(pull_http, &self.inner.endpoint, operation, cancelled, self),
            )
            .await
            .map_err(|_| OperationFailure::uncertain("Ollama pull overall deadline"))??,
            LocalModelActionKind::Update => {
                if old_digest.is_none() {
                    return Err(OperationFailure::preflight(anyhow::anyhow!(
                        "update target is not exactly installed"
                    )));
                }
                tokio::time::timeout(
                    PULL_OVERALL_TIMEOUT,
                    stream_pull(pull_http, &self.inner.endpoint, operation, cancelled, self),
                )
                .await
                .map_err(|_| OperationFailure::uncertain("Ollama update overall deadline"))??;
            }
            LocalModelActionKind::Prune => {
                let tag = tags
                    .iter()
                    .find(|tag| tag_selector(tag) == operation.model)
                    .context("prune target is absent")
                    .map_err(OperationFailure::preflight)?;
                if ps.iter().any(|loaded| same_loaded_tag(loaded, tag)) {
                    return Err(OperationFailure::preflight(anyhow::anyhow!(
                        "prune target is loaded/in use"
                    )));
                }
                delete_model(http, &self.inner.endpoint, &operation.model).await?;
                let (fresh, _) = inventory(http, &self.inner.endpoint)
                    .await
                    .map_err(OperationFailure::post_send)?;
                if fresh
                    .iter()
                    .any(|candidate| tag_selector(candidate) == operation.model)
                {
                    return Err(OperationFailure::post_send(anyhow::anyhow!(
                        "prune completion lacks fresh exact absence proof"
                    )));
                }
            }
            LocalModelActionKind::Retry => unreachable!("retry is resolved before worker creation"),
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(OperationFailure::uncertain(
                "operation cancellation requested after mutable request",
            ));
        }
        let (fresh, _) = inventory(http, &self.inner.endpoint)
            .await
            .map_err(OperationFailure::post_send)?;
        let new_digest = fresh
            .iter()
            .find(|tag| tag_selector(tag) == operation.model)
            .map(|tag| tag.digest.clone());
        if !matches!(operation.action, LocalModelActionKind::Prune) && new_digest.is_none() {
            return Err(OperationFailure::post_send(anyhow::anyhow!(
                "terminal pull/update lacks fresh exact target inventory"
            )));
        }
        Ok((old_digest, new_digest))
    }

    async fn persist_current(&self) {
        let (snapshot, revision) = {
            let state = self.inner.state.lock().await;
            (state.snapshot.clone(), state.revision)
        };
        // A delayed progress/observation write must never replace a newer
        // durable terminal record. `try_lock` also avoids lock inversion with
        // terminal persistence, which intentionally holds state fail-closed.
        let _persist = self
            .inner
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Ok(state) = self.inner.state.try_lock() else {
            return;
        };
        if state.revision != revision {
            return;
        }
        if let Err(error) = persist_unlocked(&self.inner.store, &snapshot) {
            tracing::warn!(error = %error, "persist local model status failed");
        }
    }

    fn persist_snapshot_critical(&self, snapshot: &LocalModelsSnapshot) -> Result<()> {
        #[cfg(test)]
        if self
            .inner
            .fail_critical_persist
            .swap(false, Ordering::AcqRel)
        {
            anyhow::bail!("injected local-model critical persistence failure");
        }
        persist(&self.inner.store, snapshot, &self.inner.persist_lock)
    }
    #[cfg(test)]
    pub(crate) fn fail_next_critical_persist_for_test(&self) {
        self.inner
            .fail_critical_persist
            .store(true, Ordering::Release);
    }
}

#[derive(Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<Tag>,
}
#[derive(Clone, Deserialize)]
struct Tag {
    name: String,
    #[serde(default)]
    model: String,
    digest: String,
    size: u64,
}
#[derive(Deserialize)]
struct PsResponse {
    #[serde(default)]
    models: Vec<PsModel>,
}
#[derive(Clone, Deserialize)]
struct PsModel {
    name: String,
    #[serde(default)]
    model: String,
    digest: String,
    size: u64,
    #[serde(default)]
    size_vram: Option<u64>,
    #[serde(default)]
    expires_at: Option<String>,
}
#[derive(Deserialize)]
struct ChatResponse {
    model: String,
    #[serde(default)]
    done: bool,
}
#[derive(Deserialize)]
struct PullFrame {
    #[serde(default)]
    status: String,
    #[serde(default)]
    completed: Option<u64>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}
enum ProbeFailure {
    ResponseModelMismatch,
    Other,
}

enum OperationFailure {
    Failed {
        code: LocalModelErrorCode,
        error: anyhow::Error,
    },
    Uncertain(anyhow::Error),
}

impl OperationFailure {
    fn preflight(error: anyhow::Error) -> Self {
        Self::Failed {
            code: classify_error(&error),
            error,
        }
    }

    fn post_send(error: anyhow::Error) -> Self {
        Self::Uncertain(error)
    }

    fn uncertain(detail: &str) -> Self {
        Self::Uncertain(anyhow::anyhow!(detail.to_owned()))
    }

    fn remote_rejected(detail: impl AsRef<str>) -> Self {
        Self::Failed {
            code: LocalModelErrorCode::RemoteRejected,
            error: anyhow::anyhow!(detail.as_ref().to_owned()),
        }
    }
}

fn terminal_receipt(
    operation: &LocalModelOperation,
    outcome: LocalModelTerminalOutcome,
    old_digest: Option<String>,
    new_digest: Option<String>,
    error: Option<LocalModelError>,
) -> LocalModelTerminalReceipt {
    LocalModelTerminalReceipt {
        operation_id: operation.operation_id.clone(),
        action: operation.action,
        model: operation.model.clone(),
        started_at_unix_ms: operation.started_at_unix_ms,
        finished_at_unix_ms: now_ms(),
        outcome,
        old_digest,
        new_digest,
        error,
    }
}

fn endpoint_url(endpoint: &LocalModelEndpoint, path: &str) -> String {
    format!(
        "{}/{}",
        endpoint.base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}
async fn inventory(
    http: &reqwest::Client,
    endpoint: &LocalModelEndpoint,
) -> Result<(Vec<Tag>, Vec<PsModel>)> {
    let tags =
        bounded_json::<TagsResponse>(http.get(endpoint_url(endpoint, "/api/tags")).send().await?)
            .await?;
    let ps = bounded_json::<PsResponse>(http.get(endpoint_url(endpoint, "/api/ps")).send().await?)
        .await?;
    anyhow::ensure!(
        tags.models.len() <= MAX_MODELS && ps.models.len() <= MAX_MODELS,
        "Ollama inventory exceeds cap"
    );
    Ok((tags.models, ps.models))
}
async fn bounded_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_STATE_BYTES,
            "Ollama response exceeds cap"
        );
        body.extend_from_slice(&chunk);
    }
    anyhow::ensure!(status.is_success(), "Ollama returned HTTP {}", status);
    Ok(serde_json::from_slice(&body)?)
}
async fn probe_ready(
    http: &reqwest::Client,
    endpoint: &LocalModelEndpoint,
    model: &str,
) -> std::result::Result<LoadedModelUse, ProbeFailure> {
    let response = http.post(endpoint_url(endpoint, "/api/chat")).json(&serde_json::json!({"model": model, "stream": false, "messages": [{"role":"user","content":PROBE_PROMPT}], "options":{"num_predict":1}})).send().await.map_err(|_| ProbeFailure::Other)?;
    let parsed = bounded_json::<ChatResponse>(response)
        .await
        .map_err(|_| ProbeFailure::Other)?;
    if !parsed.done || parsed.model != model {
        return Err(ProbeFailure::ResponseModelMismatch);
    }
    let (tags, ps) = inventory(http, endpoint)
        .await
        .map_err(|_| ProbeFailure::Other)?;
    let tag = tags
        .iter()
        .find(|entry| tag_selector(entry) == model)
        .ok_or(ProbeFailure::Other)?;
    ps.iter()
        .find(|loaded| same_loaded_tag(loaded, tag))
        .map(loaded_model_use)
        .ok_or(ProbeFailure::Other)
}
async fn stream_pull(
    http: &reqwest::Client,
    endpoint: &LocalModelEndpoint,
    operation: &LocalModelOperation,
    cancelled: &AtomicBool,
    controller: &LocalModelController,
) -> std::result::Result<(), OperationFailure> {
    let response = http
        .post(endpoint_url(endpoint, "/api/pull"))
        .json(&serde_json::json!({"name": operation.model, "stream": true}))
        .send()
        .await
        .map_err(|error| OperationFailure::post_send(error.into()))?;
    if !response.status().is_success() {
        return Err(OperationFailure::remote_rejected(format!(
            "Ollama pull returned HTTP {}",
            response.status()
        )));
    }
    let mut stream = response.bytes_stream();
    let mut line = Vec::new();
    let mut terminal = false;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OperationFailure::uncertain(
                "operation cancellation requested during pull",
            ));
        }
        let next = tokio::time::timeout(PULL_IDLE_TIMEOUT, stream.next())
            .await
            .map_err(|_| OperationFailure::uncertain("Ollama pull idle deadline"))?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|error| {
            OperationFailure::post_send(anyhow::anyhow!("Ollama pull transport failed: {error}"))
        })?;
        for byte in chunk {
            if byte == b'\n' {
                if line.is_empty() {
                    continue;
                }
                let frame: PullFrame = serde_json::from_slice(&line)
                    .map_err(|error| OperationFailure::post_send(error.into()))?;
                line.clear();
                if let Some(remote_error) = frame.error {
                    return Err(OperationFailure::remote_rejected(format!(
                        "Ollama pull error: {}",
                        bounded(&remote_error)
                    )));
                }
                terminal |= frame.status.eq_ignore_ascii_case("success");
                controller.update_progress(operation, frame).await;
            } else {
                if line.len() >= MAX_NDJSON_FRAME {
                    return Err(OperationFailure::post_send(anyhow::anyhow!(
                        "Ollama pull NDJSON frame exceeds cap"
                    )));
                }
                line.push(byte);
            }
        }
    }
    if !line.is_empty() {
        let frame: PullFrame = serde_json::from_slice(&line)
            .map_err(|error| OperationFailure::post_send(error.into()))?;
        if let Some(remote_error) = frame.error {
            return Err(OperationFailure::remote_rejected(format!(
                "Ollama pull error: {}",
                bounded(&remote_error)
            )));
        }
        terminal |= frame.status.eq_ignore_ascii_case("success");
        controller.update_progress(operation, frame).await;
    }
    if !terminal {
        return Err(OperationFailure::uncertain(
            "Ollama pull ended without terminal success frame",
        ));
    }
    Ok(())
}

async fn delete_model(
    http: &reqwest::Client,
    endpoint: &LocalModelEndpoint,
    model: &str,
) -> std::result::Result<(), OperationFailure> {
    let response = http
        .delete(endpoint_url(endpoint, "/api/delete"))
        .json(&serde_json::json!({"name": model}))
        .send()
        .await
        .map_err(|error| OperationFailure::post_send(error.into()))?;
    if !response.status().is_success() {
        return Err(OperationFailure::remote_rejected(format!(
            "Ollama delete returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}
impl LocalModelController {
    async fn update_progress(&self, operation: &LocalModelOperation, frame: PullFrame) {
        let mut state = self.inner.state.lock().await;
        if let Some(active) = state
            .active
            .as_mut()
            .filter(|active| active.operation.operation_id == operation.operation_id)
        {
            active.operation.progress = Some(LocalModelProgress {
                status: bounded(&frame.status),
                completed: frame.completed,
                total: frame.total,
            });
            state.snapshot.active_operation = Some(active.operation.clone());
            for row in &mut state.snapshot.models {
                if row.model == operation.model {
                    row.readiness = match operation.action {
                        LocalModelActionKind::Pull => LocalModelReadiness::Downloading {
                            operation_id: operation.operation_id.clone(),
                            completed: frame.completed,
                            total: frame.total,
                        },
                        _ => LocalModelReadiness::Updating {
                            operation_id: operation.operation_id.clone(),
                            completed: frame.completed,
                            total: frame.total,
                        },
                    };
                }
            }
            state.snapshot.observed_at_unix_ms = now_ms();
            state.revision = state.revision.wrapping_add(1);
        }
        drop(state);
        self.persist_current().await;
    }
}

fn join_inventory(tags: Vec<Tag>, ps: Vec<PsModel>) -> Vec<LocalModelRow> {
    tags.into_iter()
        .filter_map(|tag| {
            let model = tag_selector(&tag);
            if model.is_empty() || tag.digest.len() > MAX_TEXT {
                return None;
            }
            let loaded = ps
                .iter()
                .find(|entry| same_loaded_tag(entry, &tag))
                .map(loaded_model_use);
            Some(LocalModelRow {
                model: bounded(model),
                digest: bounded(&tag.digest),
                size_bytes: tag.size,
                loaded,
                readiness: LocalModelReadiness::Installed,
                last_error: None,
            })
        })
        .collect()
}
fn loaded_model_use(entry: &PsModel) -> LoadedModelUse {
    LoadedModelUse {
        model: bounded(if entry.model.is_empty() {
            &entry.name
        } else {
            &entry.model
        }),
        name: Some(bounded(&entry.name)),
        digest: bounded(&entry.digest),
        size_bytes: entry.size,
        size_vram_bytes: entry.size_vram,
        expires_at: entry.expires_at.clone().map(|value| bounded(&value)),
    }
}
fn tag_selector(tag: &Tag) -> &str {
    if tag.model.is_empty() {
        &tag.name
    } else {
        &tag.model
    }
}
fn same_loaded_tag(loaded: &PsModel, tag: &Tag) -> bool {
    let loaded_model = if loaded.model.is_empty() {
        &loaded.name
    } else {
        &loaded.model
    };
    let tag_model = if tag.model.is_empty() {
        &tag.name
    } else {
        &tag.model
    };
    loaded_model == tag_model && loaded.digest == tag.digest
}
fn suppress_ready_for_operation(rows: &mut [LocalModelRow], operation: &LocalModelOperation) {
    for row in rows.iter_mut() {
        if row.model == operation.model {
            row.readiness = match operation.action {
                LocalModelActionKind::Pull => LocalModelReadiness::Downloading {
                    operation_id: operation.operation_id.clone(),
                    completed: None,
                    total: None,
                },
                LocalModelActionKind::Update => LocalModelReadiness::Updating {
                    operation_id: operation.operation_id.clone(),
                    completed: None,
                    total: None,
                },
                LocalModelActionKind::Prune => LocalModelReadiness::Pruning {
                    operation_id: operation.operation_id.clone(),
                },
                LocalModelActionKind::Retry => LocalModelReadiness::Downloading {
                    operation_id: operation.operation_id.clone(),
                    completed: None,
                    total: None,
                },
            };
        }
    }
}
fn apply_terminal(rows: &mut Vec<LocalModelRow>, receipt: &LocalModelTerminalReceipt) {
    let mut matched = false;
    for row in rows.iter_mut() {
        if row.model == receipt.model {
            matched = true;
            match receipt.outcome {
                LocalModelTerminalOutcome::Completed => {
                    row.readiness = LocalModelReadiness::Installed
                }
                LocalModelTerminalOutcome::Failed => {
                    row.readiness = LocalModelReadiness::Failed {
                        operation_id: receipt.operation_id.clone(),
                        code: receipt
                            .error
                            .as_ref()
                            .map(|error| error.code.clone())
                            .unwrap_or(LocalModelErrorCode::Protocol),
                    };
                    row.last_error = receipt.error.clone();
                }
                LocalModelTerminalOutcome::InterruptedUnknown => {
                    row.readiness = LocalModelReadiness::InterruptedUnknown {
                        operation_id: receipt.operation_id.clone(),
                    }
                }
            }
        }
    }
    // An interrupted remote effect must remain visible even if a concurrent
    // inventory refresh omitted the target row. Do not invent an installed
    // digest or readiness proof: retain only the exact operation uncertainty.
    if !matched
        && matches!(
            receipt.outcome,
            LocalModelTerminalOutcome::InterruptedUnknown
        )
    {
        rows.push(LocalModelRow {
            model: receipt.model.clone(),
            digest: "unknown".to_owned(),
            size_bytes: 0,
            loaded: None,
            readiness: LocalModelReadiness::InterruptedUnknown {
                operation_id: receipt.operation_id.clone(),
            },
            last_error: receipt.error.clone(),
        });
    }
}
fn persist(
    store: &PersistedState,
    snapshot: &LocalModelsSnapshot,
    lock: &StdMutex<()>,
) -> Result<()> {
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    persist_unlocked(store, snapshot)
}
fn persist_unlocked(store: &PersistedState, snapshot: &LocalModelsSnapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "local model state exceeds cap"
    );
    crate::skills::store::atomic_write_private_child(
        &store.root.dir,
        OsStr::new(STATUS_FILE),
        &store.path,
        &bytes,
    )?;
    Ok(())
}
fn load_persisted(store: &PersistedState) -> Result<Option<LocalModelsSnapshot>> {
    let bytes = match crate::skills::store::read_regular_file_bounded(
        &store.root.dir,
        OsStr::new(STATUS_FILE),
        &store.path,
        MAX_STATE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let snapshot: LocalModelsSnapshot = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        snapshot.schema_version == SCHEMA_VERSION,
        "unsupported local model state schema"
    );
    anyhow::ensure!(
        snapshot.models.len() <= MAX_MODELS,
        "persisted inventory exceeds cap"
    );
    Ok(Some(snapshot))
}
fn validate_model(model: &str) -> Result<()> {
    anyhow::ensure!(
        !model.trim().is_empty()
            && model.len() <= MAX_TEXT
            && !model.bytes().any(|byte| byte.is_ascii_control()),
        "invalid model selector"
    );
    Ok(())
}
fn classify_error(error: &anyhow::Error) -> LocalModelErrorCode {
    let text = error.to_string();
    if text.contains("cancellation") {
        LocalModelErrorCode::Cancelled
    } else if text.contains("HTTP") {
        LocalModelErrorCode::RemoteRejected
    } else {
        LocalModelErrorCode::Transport
    }
}
fn err(code: LocalModelErrorCode, detail: impl AsRef<str>) -> LocalModelError {
    LocalModelError {
        code,
        detail: bounded(detail.as_ref()),
    }
}
fn bounded(value: &str) -> String {
    value.chars().take(MAX_TEXT).collect()
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn redact_origin(raw: &str) -> String {
    reqwest::Url::parse(raw)
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(|host| format!("{}://{}", url.scheme(), host))
        })
        .unwrap_or_else(|| "invalid endpoint".to_owned())
}

#[cfg(test)]
mod tests;

// The Hosted acceptance suite uses a real loopback HTTP listener instead of a
// parser-only fixture. It is deliberately source-only in the BSOD hold: no
// local fixture process is started from this worktree.
#[cfg(test)]
pub(crate) mod loopback_fixture {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;
    use tokio::task::JoinSet;

    #[derive(Clone, Debug)]
    pub(crate) struct FixtureModel {
        pub(crate) selector: String,
        pub(crate) digest: String,
        pub(crate) size: u64,
        pub(crate) loaded: bool,
    }
    #[derive(Clone, Debug)]
    pub(crate) struct FixtureScript {
        pub(crate) chat_succeeds: bool,
        pub(crate) chat_returns_requested_model: bool,
        pub(crate) chat_marks_requested_loaded: bool,
        pub(crate) ps_digest_matches: bool,
        pub(crate) pull_frames: Vec<String>,
        pub(crate) hold_pull_open: bool,
    }
    impl Default for FixtureScript {
        fn default() -> Self {
            Self {
                chat_succeeds: true,
                chat_returns_requested_model: true,
                chat_marks_requested_loaded: false,
                ps_digest_matches: true,
                pull_frames: vec![
                    r#"{"status":"pulling","completed":1,"total":2}"#.to_owned(),
                    r#"{"status":"success","completed":2,"total":2}"#.to_owned(),
                ],
                hold_pull_open: false,
            }
        }
    }
    #[derive(Clone, Default)]
    pub(crate) struct FixtureState {
        pub(crate) models: BTreeMap<String, FixtureModel>,
        pub(crate) script: FixtureScript,
        pub(crate) pulls_started: usize,
        pub(crate) deletes: Vec<String>,
        pub(crate) requests: Vec<String>,
        pub(crate) oversized_response: bool,
        pub(crate) omit_tag_model: bool,
    }
    pub(crate) struct LoopbackOllamaFixture {
        pub(crate) endpoint: String,
        pub(crate) state: Arc<Mutex<FixtureState>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl LoopbackOllamaFixture {
        pub(crate) async fn start(state: FixtureState) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("fixture listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("fixture address"));
            let shared = Arc::new(Mutex::new(state));
            let task_state = Arc::clone(&shared);
            let task = tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => match accepted {
                            Ok((stream, _)) => { let state = Arc::clone(&task_state); children.spawn(async move { let _ = serve(stream, state).await; }); }
                            Err(_) => break,
                        },
                        Some(_) = children.join_next(), if !children.is_empty() => {}
                    }
                }
            });
            Self {
                endpoint,
                state: shared,
                task,
            }
        }
        pub(crate) async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    async fn serve(mut stream: TcpStream, state: Arc<Mutex<FixtureState>>) -> std::io::Result<()> {
        let request = read_request(&mut stream).await?;
        let (method, path) = request
            .split_once(' ')
            .map(|(method, rest)| (method, rest.split_whitespace().next().unwrap_or("/")))
            .unwrap_or(("", "/"));
        let request_model = request
            .split("\r\n\r\n")
            .nth(1)
            .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .and_then(|json| {
                json.get("model")
                    .or_else(|| json.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        let (status, body, streaming) = {
            let mut guard = state.lock().await;
            guard.requests.push(request.to_string());
            match (method, path) {
                ("GET", "/api/tags") if guard.oversized_response => {
                    (200, "x".repeat(super::MAX_STATE_BYTES + 1), false)
                }
                ("GET", "/api/tags") => {
                    let models: Vec<_> = guard.models.values().map(|model| if guard.omit_tag_model { serde_json::json!({"name":model.selector,"digest":model.digest,"size":model.size}) } else { serde_json::json!({"name":model.selector,"model":model.selector,"digest":model.digest,"size":model.size}) }).collect();
                    (200, serde_json::json!({"models":models}).to_string(), false)
                }
                ("GET", "/api/ps") => {
                    let models: Vec<_> = guard.models.values().filter(|model| model.loaded).map(|model| serde_json::json!({"name":model.selector,"model":model.selector,"digest":if guard.script.ps_digest_matches { model.digest.clone() } else { "sha256:mismatch".to_owned() },"size":model.size,"size_vram":model.size / 2})).collect();
                    (200, serde_json::json!({"models":models}).to_string(), false)
                }
                ("POST", "/api/chat") if guard.script.chat_succeeds => {
                    if guard.script.chat_marks_requested_loaded
                        && let Some(requested) = request_model.as_deref()
                        && let Some(model) = guard.models.get_mut(requested)
                    {
                        model.loaded = true;
                    }
                    let model = request_model.unwrap_or_else(|| "missing".to_owned());
                    let model = if guard.script.chat_returns_requested_model {
                        model
                    } else {
                        "wrong-model".to_owned()
                    };
                    (200, serde_json::json!({"model":model,"done":true,"message":{"role":"assistant","content":"OK"}}).to_string(), false)
                }
                ("POST", "/api/chat") => (
                    500,
                    r#"{"error":"scripted chat failure"}"#.to_owned(),
                    false,
                ),
                ("POST", "/api/pull") => {
                    guard.pulls_started += 1;
                    let body = guard.script.pull_frames.join("\n") + "\n";
                    (200, body, guard.script.hold_pull_open)
                }
                ("DELETE", "/api/delete") => {
                    let target = request
                        .split("\r\n\r\n")
                        .nth(1)
                        .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
                        .and_then(|json| {
                            json.get("name")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default();
                    if guard.models.remove(&target).is_some() {
                        guard.deletes.push(target);
                        (200, "{}".to_owned(), false)
                    } else {
                        (404, r#"{"error":"missing exact target"}"#.to_owned(), false)
                    }
                }
                _ => (404, r#"{"error":"missing"}"#.to_owned(), false),
            }
        };
        let headers = if streaming {
            format!(
                "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n"
            )
        } else {
            format!(
                "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
        };
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        if streaming {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
        const MAX_REQUEST: usize = 64 * 1024;
        let mut bytes = Vec::with_capacity(4096);
        let mut scratch = [0_u8; 4096];
        let header_end = loop {
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
            if bytes.len() >= MAX_REQUEST {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture request exceeds cap",
                ));
            }
            let read = stream.read(&mut scratch).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fixture request headers truncated",
                ));
            }
            bytes.extend_from_slice(&scratch[..read]);
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture request headers are not UTF-8",
            )
        })?;
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let required = header_end
            .checked_add(content_length)
            .filter(|required| *required <= MAX_REQUEST)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture request body exceeds cap",
                )
            })?;
        while bytes.len() < required {
            let read = stream.read(&mut scratch).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fixture request body truncated",
                ));
            }
            bytes.extend_from_slice(&scratch[..read]);
        }
        Ok(String::from_utf8_lossy(&bytes[..required]).into_owned())
    }
}
