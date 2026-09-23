//! Private, same-user Connector-Control RPC boundary.
//!
//! This is intentionally a sibling of audit RPC rather than an extension of
//! it: the token filename, sidecar, Unix namespace, endpoint hash label and
//! routes are all connector-control specific.  There is no TCP fallback and
//! no request-controlled subject identity.  The daemon supplies the only
//! subject from its accepted startup configuration.

#[cfg(any(unix, windows))]
use std::collections::BTreeMap;
#[cfg(any(unix, windows))]
use std::ffi::OsStr;
#[cfg(any(unix, windows))]
use std::time::{Duration, Instant};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(any(unix, windows))]
use anyhow::Context as _;
#[cfg(any(unix, windows))]
use anyhow::ensure;
use anyhow::{Result, bail};
#[cfg(any(unix, windows))]
use base64::Engine as _;
#[cfg(any(unix, windows))]
use serde::Deserialize;
#[cfg(unix)]
use serde::Serialize;
#[cfg(any(unix, windows))]
use sha2::{Digest as _, Sha256};
#[cfg(any(unix, windows))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
#[cfg(any(unix, windows))]
use tokio::task::JoinSet;

use super::{ConnectorControlPlane, SubjectId};
#[cfg(any(unix, windows))]
use super::{ConnectorInstanceId, daemon_authenticated_session};
#[cfg(any(unix, windows))]
use crate::connectors::control_state::ConnectorLifecycle;
#[cfg(any(unix, windows))]
use crate::connectors::local_import::{approve_import_root, issue_operator_import_capability};
#[cfg(any(unix, windows))]
use crate::connectors::runtime_local_import::RuntimeLocalImport;
#[cfg(any(unix, windows))]
use crate::n8n_api::auth::AuthCooldown;
#[cfg(any(unix, windows))]
use crate::n8n_api::{constant_time_token_eq, extract_bearer_token};
use crate::wal::writer::WalWriterHandle;
#[cfg(any(unix, windows))]
use crate::{
    connectors::{
        ConnectorId,
        runtime_local_import::{ContextEvidenceReplayRuntime, ContextEvidenceWalSink},
    },
    context_graph::{ContextImportApplyKey, ContextStore},
    wal::events::ContextEvidenceReceipt,
};

const TOKEN_FILE: &str = "connector_control_rpc_token";
#[cfg(any(unix, windows))]
const SIDECAR_FILE: &str = "connector_control_rpc.endpoint.v1.json";
#[cfg(unix)]
const PREBIND_FILE: &str = "connector_control_rpc.prebind.v1.json";
#[cfg(any(unix, windows))]
const SIDECAR_SCHEMA_VERSION: u8 = 1;
#[cfg(any(unix, windows))]
const MAX_REQUEST_BYTES: usize = 8 * 1024;
#[cfg(any(unix, windows))]
const MAX_BODY_BYTES: usize = 4096;
#[cfg(any(unix, windows))]
const MAX_RESPONSE_BYTES: usize = 4096;
/// Fixed HTTP status-line and header allowance around a bounded response body.
#[cfg(any(unix, windows))]
const MAX_RESPONSE_ENVELOPE_BYTES: usize = MAX_RESPONSE_BYTES + 1024;
#[cfg(any(unix, windows))]
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
#[cfg(any(unix, windows))]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(unix, windows))]
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
#[cfg(any(unix, windows))]
const MAX_PENDING_PLANS: usize = 64;
#[cfg(unix)]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 100;
#[cfg(unix)]
const RUNTIME_ROOT_PREFIX: &str = ".n-";
#[cfg(unix)]
const HOME_NAMESPACE_PREFIX: &str = "h-";
#[cfg(unix)]
const CHANNEL_NAMESPACE_PREFIX: &str = "c-";
#[cfg(unix)]
const SOCKET_BASENAME: &str = "s";
#[cfg(unix)]
const HOME_NAMESPACE_HEX_LEN: usize = 16;
#[cfg(unix)]
const CHANNEL_NAMESPACE_HEX_LEN: usize = 16;

#[cfg(unix)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
enum Endpoint {
    #[cfg(unix)]
    UnixSocket {
        path: PathBuf,
        endpoint_nonce: String,
        home_sha256: String,
        runtime_nonce: String,
    },
}

#[cfg(unix)]
#[derive(Serialize)]
struct Sidecar<'a> {
    schema_version: u8,
    daemon_pid: u32,
    endpoint_nonce: &'a str,
    endpoint: &'a Endpoint,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSidecar {
    schema_version: u8,
    daemon_pid: u32,
    endpoint_nonce: String,
    endpoint: Endpoint,
}

#[cfg(unix)]
#[derive(Serialize)]
struct PrebindRecord<'a> {
    schema_version: u8,
    endpoint: &'a Endpoint,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPrebindRecord {
    schema_version: u8,
    endpoint: Endpoint,
}

/// Bound to daemon lifetime. Drop linearizes effect admission closed, then
/// withdraws discovery/token/socket and cooperatively signals the listener.
/// It intentionally does not abort already admitted work.
pub(crate) struct SidecarGuard {
    home: PathBuf,
    #[cfg(unix)]
    endpoint: Option<Endpoint>,
    shutdown: Arc<RpcShutdown>,
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        // Close effect admission before withdrawal, atomically with the last
        // handler-to-worker handoff. Existing admitted applies are deliberately
        // not aborted: the daemon owns and joins their SQLite/WAL terminal work
        // before the RPC task returns, so disconnect cannot create an unowned
        // background effect.
        self.shutdown.stop();
        #[cfg(unix)]
        if let Some(endpoint) = self.endpoint.take() {
            // The lifecycle-long pre-bind journal remains an exact recovery
            // locator until this cleanup succeeds. Drop cannot return an
            // error, so leave both journal and sidecar intact on failure.
            if remove_endpoint_socket_and_empty_ancestors(&self.home, &endpoint).is_err() {
                return;
            }
            if remove_sidecar_checked(&self.home).is_err()
                || remove_prebind_checked(&self.home).is_err()
            {
                return;
            }
        }
        #[cfg(windows)]
        if remove_windows_sidecar_checked(&self.home).is_err() {
            return;
        }
        remove_boot_artifacts(&self.home, None);
    }
}

/// Cooperative stop signal for the listener and its owned operation set.
/// `Drop` can only signal synchronously; `run_listener` performs the required
/// asynchronous JoinSet drain before its task completes.
struct RpcShutdown {
    stopped: AtomicBool,
    admission: Mutex<()>,
    notify: tokio::sync::Notify,
}

impl RpcShutdown {
    #[cfg(any(unix, windows, test))]
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            admission: Mutex::new(()),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn stop(&self) {
        // Linearize shutdown against a handler's final pre-effect admission.
        // If the handler wins this mutex it creates its owned worker before we
        // withdraw; if shutdown wins, no worker can be created afterward.
        // A poisoned admission mutex is fail-closed as well.
        let _admission = self.admission.lock();
        self.stopped.store(true, Ordering::Release);
        // One listener waits on this single-consumer signal. `notify_one`
        // retains a permit when its future has not yet been polled, whereas
        // `notify_waiters` could otherwise lose the synchronous Drop signal.
        self.notify.notify_one();
    }

    #[cfg(any(unix, windows, test))]
    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    #[cfg(any(unix, windows, test))]
    fn admit_blocking<T>(&self, start: impl FnOnce() -> JoinHandle<T>) -> Option<JoinHandle<T>> {
        let _admission = self.admission.lock().ok()?;
        if self.stopped.load(Ordering::Acquire) {
            None
        } else {
            Some(start())
        }
    }

    #[cfg(any(unix, windows, test))]
    async fn cancelled(&self) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let notified = self.notify.notified();
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

#[cfg(any(unix, windows))]
struct RpcState {
    token: String,
    cooldown: Arc<AuthCooldown>,
    plane: Arc<ConnectorControlPlane>,
    daemon_subject: Option<SubjectId>,
    home: PathBuf,
    config_path: PathBuf,
    writer: WalWriterHandle,
    plans: Mutex<PlanRegistry>,
}

#[cfg(any(unix, windows))]
struct PlanRegistry {
    planning: BTreeMap<String, Instant>,
    pending: BTreeMap<String, PendingPlan>,
}

#[cfg(any(unix, windows))]
struct PendingPlan {
    runtime: RuntimeLocalImport,
    local_plan_id: crate::connectors::local_import::LocalImportPlanId,
    confirmation_nonce: String,
    expires_at: Instant,
}

#[cfg(any(unix, windows))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    root: String,
    relative_path: String,
}

#[cfg(any(unix, windows))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    plan_id: String,
    confirmation_nonce: String,
}

#[cfg(any(unix, windows))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleRequest {
    policy_revision: u64,
    lifecycle_revision: u64,
}

/// Start the private control endpoint. `audit_pid_nonce` has already been
/// committed to the held daemon PID lock; the connector nonce is a
/// domain-separated digest of it, so discovery cannot substitute audit's
/// namespace while still retaining the PID ownership binding.
#[cfg(unix)]
pub(crate) async fn bind_and_serve(
    home: &Path,
    config_path: &Path,
    audit_pid_nonce: &str,
    plane: Arc<ConnectorControlPlane>,
    daemon_subject: Option<SubjectId>,
    writer: WalWriterHandle,
) -> Result<(JoinHandle<Result<()>>, SidecarGuard)> {
    validate_nonce(audit_pid_nonce)?;
    let endpoint_nonce = connector_nonce(audit_pid_nonce);
    // `write_key_securely` is intentionally create-new.  Remove only this
    // endpoint's stale discovery/token first so a crash cannot poison the
    // next daemon boot, and never reuse audit-RPC names or credentials.
    cleanup_prior_boot_artifacts(home)?;
    let token = init_token(home)?;
    let endpoint = match bind_endpoint(home, &endpoint_nonce) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            remove_boot_artifacts(home, None);
            return Err(error);
        }
    };
    #[cfg(unix)]
    let listener = match bind_listener(&endpoint) {
        Ok(listener) => listener,
        Err(error) => {
            if let Err(cleanup_error) = remove_endpoint_socket_and_empty_ancestors(home, &endpoint)
            {
                return Err(cleanup_error).context(
                    "retain connector-control pre-bind journal after listener cleanup failure",
                );
            }
            remove_prebind_checked(home)?;
            remove_boot_artifacts(home, None);
            return Err(error);
        }
    };
    let state = Arc::new(RpcState {
        token,
        cooldown: Arc::new(AuthCooldown::new()),
        plane,
        daemon_subject,
        home: home.to_path_buf(),
        config_path: config_path.to_path_buf(),
        writer,
        plans: Mutex::new(PlanRegistry {
            planning: BTreeMap::new(),
            pending: BTreeMap::new(),
        }),
    });
    let shutdown = Arc::new(RpcShutdown::new());
    if let Err(error) = write_sidecar(home, &endpoint, &endpoint_nonce) {
        // The accept loop is not spawned until authenticated discovery is
        // durable, so sidecar failure cannot race an admitted connection.
        drop(listener);
        if let Err(cleanup_error) = remove_endpoint_socket_and_empty_ancestors(home, &endpoint) {
            return Err(cleanup_error).context(
                "retain connector-control sidecar and pre-bind journal after cleanup failure",
            );
        }
        remove_sidecar_checked(home)?;
        remove_prebind_checked(home)?;
        remove_boot_artifacts(home, None);
        return Err(error).context("publish connector-control RPC sidecar");
    }
    let endpoint_for_task = endpoint.clone();
    let task = {
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(
            async move { run_listener(listener, endpoint_for_task, state, shutdown).await },
        )
    };
    Ok((
        task,
        SidecarGuard {
            home: home.to_path_buf(),
            endpoint: Some(endpoint),
            shutdown,
        },
    ))
}

/// Bind the Windows listener using a distinct connector-control pipe service.
/// Its per-boot token is never an audit token, and the service identifier
/// prevents a valid audit endpoint from substituting this control authority.
#[cfg(windows)]
pub(crate) async fn bind_and_serve(
    home: &Path,
    config_path: &Path,
    audit_pid_nonce: &str,
    plane: Arc<ConnectorControlPlane>,
    daemon_subject: Option<SubjectId>,
    writer: WalWriterHandle,
) -> Result<(JoinHandle<Result<()>>, SidecarGuard)> {
    validate_nonce(audit_pid_nonce)?;
    let endpoint_nonce = connector_nonce(audit_pid_nonce);
    remove_windows_sidecar_checked(home)?;
    remove_boot_artifacts(home, None);
    let token = init_token(home)?;
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let home_sha256 = hex::encode(Sha256::digest(
        canonical_home.as_os_str().as_encoded_bytes(),
    ));
    let endpoint = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
        "neoth-cc-v1",
        &home_sha256,
        &endpoint_nonce,
    )?;
    let listener =
        crate::windows_private_ipc::Listener::bind(endpoint.clone(), MAX_REQUEST_BYTES as u32)?;
    let state = Arc::new(RpcState {
        token,
        cooldown: Arc::new(AuthCooldown::new()),
        plane,
        daemon_subject,
        home: home.to_path_buf(),
        config_path: config_path.to_path_buf(),
        writer,
        plans: Mutex::new(PlanRegistry {
            planning: BTreeMap::new(),
            pending: BTreeMap::new(),
        }),
    });
    let shutdown = Arc::new(RpcShutdown::new());
    if let Err(error) = write_windows_sidecar(home, &endpoint_nonce, &home_sha256, &endpoint) {
        drop(listener);
        remove_boot_artifacts(home, None);
        return Err(error).context("publish connector-control Windows sidecar");
    }
    let task = {
        let shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move { run_windows_listener(listener, state, shutdown).await })
    };
    Ok((
        task,
        SidecarGuard {
            home: home.to_path_buf(),
            shutdown,
        },
    ))
}

/// Other targets deliberately expose no connector-control transport: there is
/// no TCP or un-attested pipe fallback.
#[cfg(not(any(unix, windows)))]
pub(crate) async fn bind_and_serve(
    _: &Path,
    _: &Path,
    _: &str,
    _: Arc<ConnectorControlPlane>,
    _: Option<SubjectId>,
    _: WalWriterHandle,
) -> Result<(JoinHandle<Result<()>>, SidecarGuard)> {
    bail!("connector-control RPC is unavailable on this platform; no TCP fallback exists")
}

/// Reconstruct plan-independent recovery before the CC endpoint is published.
/// It first removes uncommitted reservations whose in-memory plans died with
/// the prior process, then drains receipts. It owns no root, plan, path, or
/// imported content; the private daemon session authorizes only the exact
/// LocalImport account binding, and every cleanup/reserve/conditional ACK
/// still receives a fresh operation lease.
///
/// A failed authenticated append or conditional ACK blocks startup rather than
/// advertising a daemon whose committed Context Evidence cannot be recovered.
#[cfg(any(unix, windows))]
pub(crate) async fn replay_pending_context_evidence_at_startup(
    home: &Path,
    plane: Arc<ConnectorControlPlane>,
    daemon_subject: Option<SubjectId>,
    writer: WalWriterHandle,
) -> Result<usize> {
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let subject =
            daemon_subject.context("daemon has no configured connector-control subject")?;
        let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
        let authority =
            plane.authorize_context_import(&daemon_authenticated_session(subject), &instance)?;
        let binding = authority.acquire_context_import_runtime()?;
        let key = crate::wal::master_key::load_existing_master_key_at(&home)?;
        let store = ContextStore::open_at(home.join("context.db"), &key)?;
        let mut replay = ContextEvidenceReplayRuntime::new(binding, store);
        replay.reclaim_uncommitted_apply_outcomes()?;
        let mut sink = DaemonWalSink { writer };
        replay.replay_receipts(&mut sink)
    })
    .await
    .map_err(|_| anyhow::anyhow!("connector-control startup replay worker panicked"))?
}

fn remove_boot_artifacts(home: &Path, socket_path: Option<PathBuf>) {
    let token_path = home.join(TOKEN_FILE);
    if token_path.exists() {
        let _ = crate::util::atomic_write::durable_remove_file(&token_path);
    }
    if let Some(path) = socket_path {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(windows)]
fn write_windows_sidecar(
    home: &Path,
    endpoint_nonce: &str,
    home_sha256: &str,
    endpoint: &crate::windows_private_ipc::PrivatePipeEndpoint,
) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "daemon_pid": std::process::id(),
        "endpoint_nonce": endpoint_nonce,
        "transport": "windows_named_pipe",
        "name": endpoint.name(),
        "home_sha256": home_sha256,
    }))?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "connector-control sidecar exceeds cap"
    );
    let trusted_anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        home,
        true,
        "connector-control Windows sidecar directory",
    )?
    .context("connector-control Windows sidecar directory was not created")?;
    let path = bound.display_path.join(SIDECAR_FILE);
    crate::skills::store::atomic_write_private_child(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
        &body,
    )?;
    let persisted = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
        MAX_RESPONSE_BYTES,
    )?;
    ensure!(
        persisted == body,
        "connector-control Windows sidecar changed during publication"
    );
    Ok(())
}

#[cfg(windows)]
fn remove_windows_sidecar_checked(home: &Path) -> Result<()> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control Windows sidecar directory",
    )?
    else {
        return Ok(());
    };
    let path = bound.display_path.join(SIDECAR_FILE);
    crate::skills::store::remove_child_file_if_present(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
    )?;
    Ok(())
}

/// Windows CC client discovery deliberately reads only CC-owned material. It
/// derives the expected `neoth-cc-v1` endpoint from the caller's canonical
/// home and PID-bound audit nonce, then rejects a substituted sidecar before
/// opening a named pipe.
#[cfg(windows)]
pub(crate) struct WindowsClient {
    endpoint: crate::windows_private_ipc::PrivatePipeEndpoint,
    token: String,
}

#[cfg(windows)]
pub(crate) fn windows_client(home: &Path, audit_pid_nonce: &str) -> Result<WindowsClient> {
    validate_nonce(audit_pid_nonce)?;
    let endpoint_nonce = connector_nonce(audit_pid_nonce);
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let home_sha256 = hex::encode(Sha256::digest(
        canonical_home.as_os_str().as_encoded_bytes(),
    ));
    let expected = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
        "neoth-cc-v1",
        &home_sha256,
        &endpoint_nonce,
    )?;
    let bound = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control Windows client discovery directory",
    )?
    .context("connector-control home is absent")?;
    let sidecar_path = bound.display_path.join(SIDECAR_FILE);
    let sidecar = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &sidecar_path,
        MAX_RESPONSE_BYTES,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&sidecar)?;
    let object = value
        .as_object()
        .context("connector-control Windows sidecar is not an object")?;
    ensure!(
        object.len() == 6
            && object
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(u64::from(SIDECAR_SCHEMA_VERSION))
            && object
                .get("daemon_pid")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|pid| pid != 0)
            && object
                .get("endpoint_nonce")
                .and_then(serde_json::Value::as_str)
                == Some(&endpoint_nonce)
            && object.get("transport").and_then(serde_json::Value::as_str)
                == Some("windows_named_pipe")
            && object.get("name").and_then(serde_json::Value::as_str) == Some(expected.name())
            && object
                .get("home_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(&home_sha256),
        "connector-control Windows sidecar is not bound to this daemon, home, and nonce"
    );
    let token_path = bound.display_path.join(TOKEN_FILE);
    let token_body = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(TOKEN_FILE),
        &token_path,
        MAX_RESPONSE_BYTES,
    )?;
    let token = String::from_utf8(crate::wal::compaction::maybe_unwrap_dpapi(
        &token_body,
        &token_path,
    )?)?
    .trim()
    .to_owned();
    ensure!(!token.is_empty(), "connector-control token is empty");
    Ok(WindowsClient {
        endpoint: expected,
        token,
    })
}

/// Unix discovery uses Connector-Control's own sidecar and bearer. The
/// Audit-RPC nonce merely proves the live daemon PID lock; it is never reused
/// as an audit endpoint, transport, or bearer.
#[cfg(unix)]
pub(crate) struct UnixClient {
    endpoint: Endpoint,
    token: String,
}

#[cfg(unix)]
pub(crate) fn unix_client(home: &Path, audit_pid_nonce: &str) -> Result<UnixClient> {
    validate_nonce(audit_pid_nonce)?;
    let endpoint_nonce = connector_nonce(audit_pid_nonce);
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let bound = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control Unix client discovery directory",
    )?
    .context("connector-control home is absent")?;
    let sidecar_path = bound.display_path.join(SIDECAR_FILE);
    let sidecar_body = read_unix_private_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &sidecar_path,
        MAX_RESPONSE_BYTES,
    )?;
    let sidecar: PersistedSidecar = serde_json::from_slice(&sidecar_body)
        .context("parse connector-control Unix discovery sidecar")?;
    ensure!(
        sidecar.schema_version == SIDECAR_SCHEMA_VERSION && sidecar.daemon_pid != 0,
        "connector-control Unix sidecar has an unsupported schema or daemon binding"
    );
    ensure!(
        sidecar.endpoint_nonce == endpoint_nonce,
        "connector-control Unix sidecar endpoint nonce is not bound to this daemon"
    );
    ensure!(
        crate::daemon::pidfile::live_daemon_endpoint(
            &canonical_home.join("neothd.pid"),
            sidecar.daemon_pid,
            audit_pid_nonce,
        )?,
        "connector-control Unix sidecar daemon PID does not own the exact audit endpoint"
    );
    let Endpoint::UnixSocket {
        endpoint_nonce: sidecar_endpoint_nonce,
        home_sha256,
        runtime_nonce,
        ..
    } = &sidecar.endpoint;
    ensure!(
        sidecar_endpoint_nonce == &sidecar.endpoint_nonce,
        "connector-control Unix sidecar endpoint nonce does not match its endpoint"
    );
    let expected = endpoint_for_home_with_runtime_nonce(
        &canonical_home,
        &sidecar.endpoint_nonce,
        runtime_nonce,
    )?;
    ensure!(
        sidecar.endpoint == expected,
        "connector-control Unix sidecar endpoint is not bound to canonical home and nonce"
    );
    let Endpoint::UnixSocket {
        home_sha256: expected_home_sha256,
        ..
    } = &expected;
    ensure!(
        home_sha256 == expected_home_sha256,
        "connector-control Unix sidecar home hash is not bound to canonical home"
    );
    let token_path = bound.display_path.join(TOKEN_FILE);
    let token_body = read_unix_private_regular_file_bounded(
        &bound.dir,
        OsStr::new(TOKEN_FILE),
        &token_path,
        MAX_RESPONSE_BYTES,
    )?;
    let token = String::from_utf8(crate::wal::compaction::maybe_unwrap_dpapi(
        &token_body,
        &token_path,
    )?)?
    .trim()
    .to_owned();
    ensure!(!token.is_empty(), "connector-control token is empty");
    Ok(UnixClient {
        endpoint: sidecar.endpoint,
        token,
    })
}

#[cfg(unix)]
fn read_unix_private_regular_file_bounded(
    parent: &cap_std::fs::Dir,
    name: &OsStr,
    display_path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    use cap_std::fs::MetadataExt as _;
    use std::io::Read as _;

    // `open_bound_regular_file` opens this exact direct child through the
    // retained directory capability with no-follow and O_NONBLOCK on Unix.
    // Classify and bound-read that same descriptor; never validate an ambient
    // path and then reopen its name.
    let (mut file, _binding) =
        crate::skills::store::open_bound_regular_file(parent, name, display_path)?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect connector-control Unix file {}",
            display_path.display()
        )
    })?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o600,
        "connector-control Unix discovery file is not an effective-user private regular file"
    );
    let sentinel = max_bytes
        .checked_add(1)
        .context("connector-control Unix discovery file cap overflow")?;
    let mut body = Vec::with_capacity(max_bytes);
    file.take(sentinel as u64)
        .read_to_end(&mut body)
        .with_context(|| {
            format!(
                "read connector-control Unix file {}",
                display_path.display()
            )
        })?;
    ensure!(
        body.len() <= max_bytes,
        "connector-control Unix discovery file exceeds cap"
    );
    Ok(body)
}

#[cfg(all(unix, test))]
pub(crate) fn unix_client_with_token_for_test(
    home: &Path,
    audit_pid_nonce: &str,
    token: String,
) -> Result<UnixClient> {
    let mut client = unix_client(home, audit_pid_nonce)?;
    client.token = token;
    Ok(client)
}

#[cfg(unix)]
impl UnixClient {
    pub(crate) async fn post(&self, route: &str, body: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            body.len() <= MAX_BODY_BYTES,
            "connector-control client body exceeds cap"
        );
        let request = format!(
            "POST {route} HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.token,
            body.len(),
        );
        let before = verify_unix_client_endpoint(&self.endpoint)?;
        let response = tokio::time::timeout(CONNECTION_TIMEOUT, async {
            let Endpoint::UnixSocket { path, .. } = &self.endpoint;
            let mut stream = tokio::net::UnixStream::connect(path)
                .await
                .with_context(|| {
                    format!("connect connector-control Unix socket {}", path.display())
                })?;
            ensure!(
                same_effective_uid(&stream),
                "connector-control Unix peer UID does not match the effective UID"
            );
            let after = verify_unix_client_endpoint(&self.endpoint)?;
            ensure!(
                before == after,
                "connector-control Unix endpoint changed while connecting"
            );
            stream.write_all(request.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.shutdown().await?;
            read_bounded_unix_response(&mut stream).await
        })
        .await
        .context("connector-control Unix client request deadline exceeded")??;
        validate_unix_success_response(&response)?;
        Ok(response)
    }
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct UnixEndpointIdentity {
    runtime_root: (u64, u64),
    home_namespace: (u64, u64),
    channel_namespace: (u64, u64),
    socket: (u64, u64),
}

#[cfg(unix)]
fn verify_unix_client_endpoint(endpoint: &Endpoint) -> Result<UnixEndpointIdentity> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let Endpoint::UnixSocket {
        path,
        endpoint_nonce,
        home_sha256,
        runtime_nonce,
    } = endpoint;
    let expected = endpoint_for_home_hash(home_sha256, endpoint_nonce, runtime_nonce)?;
    ensure!(
        endpoint == &expected,
        "connector-control Unix client endpoint is not the exact derived endpoint"
    );
    let channel_namespace = path
        .parent()
        .context("connector-control Unix socket has no channel namespace")?;
    let home_namespace = channel_namespace
        .parent()
        .context("connector-control Unix socket has no home namespace")?;
    let runtime_root = home_namespace
        .parent()
        .context("connector-control Unix socket has no runtime root")?;
    let runtime_parent = runtime_root
        .parent()
        .context("connector-control Unix runtime root has no parent")?;
    validate_safe_fallback_parent(runtime_parent)?;
    let runtime_root_identity = validate_private_runtime_directory_identity(
        runtime_root,
        "connector-control Unix client runtime root",
    )?;
    let home_namespace_identity = validate_private_runtime_directory_identity(
        home_namespace,
        "connector-control Unix client home namespace",
    )?;
    let channel_namespace_identity = validate_private_runtime_directory_identity(
        channel_namespace,
        "connector-control Unix client channel namespace",
    )?;
    let socket = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect connector-control Unix socket {}", path.display()))?;
    ensure!(
        socket.file_type().is_socket()
            && !socket.file_type().is_symlink()
            && socket.uid() == unsafe { libc::geteuid() }
            && socket.mode() & 0o777 == 0o600,
        "connector-control Unix socket is not an effective-user private socket"
    );
    Ok(UnixEndpointIdentity {
        runtime_root: runtime_root_identity,
        home_namespace: home_namespace_identity,
        channel_namespace: channel_namespace_identity,
        socket: (socket.dev(), socket.ino()),
    })
}

#[cfg(unix)]
fn validate_private_runtime_directory_identity(path: &Path, label: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect private {label} {}", path.display()))?;
    ensure!(
        private_directory_metadata_matches_owner(&metadata, unsafe { libc::geteuid() }),
        "{label} is not current-user private"
    );
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
async fn read_bounded_unix_response(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>> {
    let sentinel_limit = MAX_RESPONSE_ENVELOPE_BYTES
        .checked_add(1)
        .context("connector-control Unix response cap overflow")?;
    let mut response = Vec::with_capacity(MAX_RESPONSE_ENVELOPE_BYTES);
    stream
        .take(sentinel_limit as u64)
        .read_to_end(&mut response)
        .await
        .context("read connector-control Unix response")?;
    ensure!(
        response.len() <= MAX_RESPONSE_ENVELOPE_BYTES,
        "connector-control Unix response envelope exceeds cap"
    );
    Ok(response)
}

#[cfg(unix)]
fn validate_unix_success_response(response: &[u8]) -> Result<()> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("connector-control Unix response has no header boundary")?;
    let headers = std::str::from_utf8(&response[..separator])
        .context("connector-control Unix response headers are not UTF-8")?;
    let body = &response[separator + 4..];
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .context("connector-control Unix response has no status line")?;
    ensure!(
        status.starts_with("HTTP/1.1 ") && status.len() >= 12,
        "connector-control Unix response status line is malformed"
    );
    let status_bytes = status.as_bytes();
    ensure!(
        status_bytes[9..12].iter().all(u8::is_ascii_digit),
        "connector-control Unix response status code is malformed"
    );
    let status_code: u16 = std::str::from_utf8(&status_bytes[9..12])
        .expect("ASCII status digits are valid UTF-8")
        .parse()
        .context("connector-control Unix response status code is malformed")?;
    ensure!(
        status.len() == 12 || status_bytes.get(12) == Some(&b' '),
        "connector-control Unix response status line is malformed"
    );
    let mut content_length = None;
    for line in lines {
        ensure!(
            !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t'),
            "connector-control Unix response header is malformed"
        );
        let (name, value) = line
            .split_once(':')
            .context("connector-control Unix response header is malformed")?;
        ensure!(
            !name.is_empty(),
            "connector-control Unix response header has no name"
        );
        if name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("connector-control Unix response uses unsupported transfer encoding");
        }
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(
                content_length.is_none(),
                "connector-control Unix response has duplicate Content-Length"
            );
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("connector-control Unix response Content-Length is malformed")?,
            );
        }
    }
    let content_length =
        content_length.context("connector-control Unix response has no Content-Length")?;
    ensure!(
        content_length <= MAX_RESPONSE_BYTES,
        "connector-control Unix response body exceeds cap"
    );
    ensure!(
        body.len() == content_length,
        "connector-control Unix response body is truncated or has trailing bytes"
    );
    ensure!(
        status_code == 200,
        "connector-control daemon rejected request with HTTP {status_code}"
    );
    Ok(())
}

#[cfg(all(windows, test))]
pub(crate) fn windows_client_with_token_for_test(
    home: &Path,
    audit_pid_nonce: &str,
    token: String,
) -> Result<WindowsClient> {
    let mut client = windows_client(home, audit_pid_nonce)?;
    client.token = token;
    Ok(client)
}

#[cfg(windows)]
impl WindowsClient {
    pub(crate) async fn post(&self, route: &str, body: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            body.len() <= MAX_BODY_BYTES,
            "connector-control client body exceeds cap"
        );
        let request = format!(
            "POST {route} HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.token,
            body.len(),
        );
        let mut stream = crate::windows_private_ipc::connect(&self.endpoint).await?;
        let response = tokio::time::timeout(CONNECTION_TIMEOUT, async {
            stream.write_all(request.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.shutdown().await?;
            read_bounded_windows_response(&mut stream).await
        })
        .await
        .context("connector-control client request deadline exceeded")??;
        let response_text =
            std::str::from_utf8(&response).context("connector-control response is not UTF-8")?;
        ensure!(
            response_text.starts_with("HTTP/1.1 200 "),
            "connector-control daemon rejected request"
        );
        Ok(response)
    }
}

/// Receive one connector-control response without trusting a same-user peer to
/// close the pipe at the service envelope limit.
#[cfg(windows)]
async fn read_bounded_windows_response(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>> {
    let sentinel_limit = MAX_RESPONSE_ENVELOPE_BYTES
        .checked_add(1)
        .context("connector-control response cap overflow")?;
    let mut response = Vec::with_capacity(MAX_RESPONSE_ENVELOPE_BYTES);
    stream
        .take(sentinel_limit as u64)
        .read_to_end(&mut response)
        .await
        .context("read connector-control response")?;
    ensure!(
        response.len() <= MAX_RESPONSE_ENVELOPE_BYTES,
        "connector-control client response envelope exceeds cap"
    );
    Ok(response)
}

#[cfg(unix)]
fn cleanup_prior_boot_artifacts(home: &Path) -> Result<()> {
    // Keep discovery intact until the entire persisted record has been
    // authenticated against this canonical home and the exact socket leaf has
    // been removed. A malformed sidecar is evidence of an unsafe namespace,
    // not permission to unlink an attacker-selected same-UID socket.
    let sidecar_endpoint = read_prior_sidecar_endpoint(home)?;
    let prebind_endpoint = read_prior_prebind_endpoint(home)?;
    if let Some(endpoint) = &sidecar_endpoint {
        remove_endpoint_socket_and_empty_ancestors(home, endpoint)?;
    }
    if let Some(endpoint) = &prebind_endpoint
        && sidecar_endpoint.as_ref() != Some(endpoint)
    {
        remove_endpoint_socket_and_empty_ancestors(home, endpoint)?;
    }
    remove_sidecar_checked(home)?;
    remove_prebind_checked(home)?;
    remove_boot_artifacts(home, None);
    Ok(())
}

#[cfg(unix)]
fn read_prior_sidecar_endpoint(home: &Path) -> Result<Option<Endpoint>> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control RPC sidecar directory",
    )?
    else {
        return Ok(None);
    };
    let path = bound.display_path.join(SIDECAR_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let body = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
        MAX_RESPONSE_BYTES,
    )?;
    let sidecar: PersistedSidecar = serde_json::from_slice(&body)
        .context("parse prior connector-control sidecar for exact stale cleanup")?;
    ensure!(
        sidecar.schema_version == SIDECAR_SCHEMA_VERSION,
        "prior connector-control sidecar schema is unsupported"
    );
    ensure!(
        sidecar.daemon_pid != 0,
        "prior connector-control sidecar has no daemon binding"
    );
    validate_nonce(&sidecar.endpoint_nonce)?;
    let Endpoint::UnixSocket {
        endpoint_nonce,
        home_sha256,
        runtime_nonce,
        ..
    } = &sidecar.endpoint;
    ensure!(
        endpoint_nonce == &sidecar.endpoint_nonce,
        "prior connector-control sidecar endpoint nonce does not match its daemon binding"
    );
    let expected =
        endpoint_for_home_with_runtime_nonce(home, &sidecar.endpoint_nonce, runtime_nonce)?;
    ensure!(
        sidecar.endpoint == expected,
        "prior connector-control sidecar endpoint is not bound to canonical home and endpoint nonce"
    );
    let Endpoint::UnixSocket {
        home_sha256: expected_home_sha256,
        ..
    } = expected;
    ensure!(
        home_sha256 == &expected_home_sha256,
        "prior connector-control sidecar home hash is not bound to canonical home"
    );
    Ok(Some(sidecar.endpoint))
}

#[cfg(unix)]
fn read_prior_prebind_endpoint(home: &Path) -> Result<Option<Endpoint>> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control RPC pre-bind journal directory",
    )?
    else {
        return Ok(None);
    };
    let path = bound.display_path.join(PREBIND_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let body = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(PREBIND_FILE),
        &path,
        MAX_RESPONSE_BYTES,
    )?;
    let journal: PersistedPrebindRecord = serde_json::from_slice(&body)
        .context("parse connector-control pre-bind journal for exact stale cleanup")?;
    ensure!(
        journal.schema_version == SIDECAR_SCHEMA_VERSION,
        "connector-control pre-bind journal schema is unsupported"
    );
    let Endpoint::UnixSocket {
        endpoint_nonce,
        runtime_nonce,
        ..
    } = &journal.endpoint;
    let expected = endpoint_for_home_with_runtime_nonce(home, endpoint_nonce, runtime_nonce)?;
    ensure!(
        journal.endpoint == expected,
        "connector-control pre-bind journal endpoint is not bound to canonical home and nonce"
    );
    Ok(Some(journal.endpoint))
}

#[cfg(unix)]
fn remove_endpoint_socket_and_empty_ancestors(home: &Path, endpoint: &Endpoint) -> Result<()> {
    let Endpoint::UnixSocket {
        path,
        endpoint_nonce,
        home_sha256,
        runtime_nonce,
    } = endpoint;
    let expected = endpoint_for_home_with_runtime_nonce(home, endpoint_nonce, runtime_nonce)?;
    ensure!(
        endpoint == &expected,
        "connector-control socket cleanup requires the exact canonical endpoint"
    );
    let Endpoint::UnixSocket {
        home_sha256: expected_home_sha256,
        ..
    } = expected;
    ensure!(
        home_sha256 == &expected_home_sha256,
        "connector-control socket cleanup home hash does not match canonical home"
    );
    remove_exact_private_socket_and_empty_ancestors(path)
}

#[cfg(unix)]
fn remove_exact_private_socket_and_empty_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let channel_root = path
        .parent()
        .context("connector-control stale socket has no parent")?;
    let home_root = channel_root
        .parent()
        .context("connector-control stale socket has no home namespace")?;
    let runtime_root = home_root
        .parent()
        .context("connector-control stale socket has no runtime root")?;
    let runtime_parent = runtime_root
        .parent()
        .context("connector-control stale socket runtime root has no parent")?;
    match std::fs::symlink_metadata(runtime_root) {
        Ok(_) => validate_private_runtime_directory(
            runtime_root,
            "connector-control stale socket runtime root",
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A prior crash may have happened after rmdir(runtime_root) but
            // before the parent namespace reached stable storage. Sync the
            // resolved (never `/tmp` alias) parent before retiring the exact
            // journal, otherwise the directory could resurrect after loss.
            sync_directory(runtime_parent)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    match std::fs::symlink_metadata(home_root) {
        Ok(_) => validate_private_runtime_directory(
            home_root,
            "connector-control stale socket home root",
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_dir(runtime_root)?;
            sync_directory(runtime_parent)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    match std::fs::symlink_metadata(channel_root) {
        Ok(_) => validate_private_runtime_directory(
            channel_root,
            "connector-control stale socket channel root",
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_dir(home_root)?;
            sync_directory(runtime_root)?;
            std::fs::remove_dir(runtime_root)?;
            sync_directory(runtime_parent)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() },
                "connector-control exact endpoint is not a current-user socket"
            );
            std::fs::remove_file(path)?;
            sync_directory(channel_root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Each random root contains only this fixed home/channel/leaf path. A
    // non-empty ancestor therefore indicates an unexpected artifact; retain it
    // and fail rather than recursively sweeping an untrusted sibling.
    std::fs::remove_dir(channel_root)?;
    sync_directory(home_root)?;
    std::fs::remove_dir(home_root)?;
    sync_directory(runtime_root)?;
    std::fs::remove_dir(runtime_root)?;
    sync_directory(runtime_parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        path,
        false,
        "connector-control cleanup directory",
    )?
    else {
        bail!(
            "connector-control cleanup directory disappeared: {}",
            path.display()
        );
    };
    crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
        .context("make connector-control cleanup deletion durable")
        .map(|_| ())
}

#[cfg(any(unix, windows))]
fn init_token(home: &Path) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).context("OS RNG unavailable for connector-control RPC token")?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    std::fs::create_dir_all(home)
        .with_context(|| format!("create NEOTH home {}", home.display()))?;
    crate::wal::compaction::write_key_securely(&home.join(TOKEN_FILE), token.as_bytes())
        .context("write connector-control RPC token")?;
    Ok(token)
}

#[cfg(unix)]
fn write_sidecar(home: &Path, endpoint: &Endpoint, endpoint_nonce: &str) -> Result<()> {
    let body = serde_json::to_vec(&Sidecar {
        schema_version: SIDECAR_SCHEMA_VERSION,
        daemon_pid: std::process::id(),
        endpoint_nonce,
        endpoint,
    })?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "connector-control sidecar exceeds cap"
    );
    let trusted_anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        home,
        true,
        "connector-control RPC sidecar directory",
    )?
    .context("connector-control RPC sidecar directory was not created")?;
    let path = bound.display_path.join(SIDECAR_FILE);
    crate::skills::store::atomic_write_private_child(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
        &body,
    )
    .with_context(|| {
        format!(
            "write capability-bound connector-control sidecar {}",
            path.display()
        )
    })?;
    let persisted = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
        MAX_RESPONSE_BYTES,
    )?;
    ensure!(
        persisted == body,
        "connector-control sidecar namespace changed during publication"
    );
    crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
        .context("make connector-control sidecar namespace commit durable")
        .map(|_| ())
}

#[cfg(unix)]
fn write_prebind(home: &Path, endpoint: &Endpoint) -> Result<()> {
    let body = serde_json::to_vec(&PrebindRecord {
        schema_version: SIDECAR_SCHEMA_VERSION,
        endpoint,
    })?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "connector-control pre-bind journal exceeds cap"
    );
    let trusted_anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        home,
        true,
        "connector-control RPC pre-bind journal directory",
    )?
    .context("connector-control RPC pre-bind journal directory was not created")?;
    let path = bound.display_path.join(PREBIND_FILE);
    crate::skills::store::atomic_write_private_child(
        &bound.dir,
        OsStr::new(PREBIND_FILE),
        &path,
        &body,
    )?;
    let persisted = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(PREBIND_FILE),
        &path,
        MAX_RESPONSE_BYTES,
    )?;
    ensure!(
        persisted == body,
        "connector-control pre-bind journal namespace changed during publication"
    );
    crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
        .context("make connector-control pre-bind journal durable")
        .map(|_| ())
}

#[cfg(unix)]
fn remove_sidecar_checked(home: &Path) -> Result<()> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control RPC sidecar directory",
    )?
    else {
        return Ok(());
    };
    let path = bound.display_path.join(SIDECAR_FILE);
    match crate::skills::store::remove_child_file_if_present(
        &bound.dir,
        OsStr::new(SIDECAR_FILE),
        &path,
    )? {
        true => crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
            .context("make connector-control sidecar removal durable")
            .map(|_| ()),
        false => Ok(()),
    }
}

#[cfg(unix)]
fn remove_prebind_checked(home: &Path) -> Result<()> {
    let Some(bound) = crate::skills::store::open_bound_directory(
        home,
        false,
        "connector-control RPC pre-bind journal directory",
    )?
    else {
        return Ok(());
    };
    let path = bound.display_path.join(PREBIND_FILE);
    match crate::skills::store::remove_child_file_if_present(
        &bound.dir,
        OsStr::new(PREBIND_FILE),
        &path,
    )? {
        true => crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
            .context("make connector-control pre-bind journal removal durable")
            .map(|_| ()),
        false => Ok(()),
    }
}

#[cfg(any(unix, windows))]
fn connector_nonce(audit_pid_nonce: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth-connector-control-rpc-v1-endpoint-nonce\0");
    digest.update(audit_pid_nonce.as_bytes());
    hex::encode(digest.finalize())[..32].to_owned()
}

#[cfg(any(unix, windows))]
fn validate_nonce(nonce: &str) -> Result<()> {
    ensure!(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "connector-control endpoint nonce must be 32 lowercase hex characters"
    );
    Ok(())
}

#[cfg(unix)]
fn validate_home_sha256(home_sha256: &str) -> Result<()> {
    ensure!(
        home_sha256.len() == 64
            && home_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "connector-control canonical-home SHA-256 must be 64 lowercase hex characters"
    );
    Ok(())
}

/// Convert the daemon's legacy `operator_id` only when this Unix CC instance
/// actually requires LocalImport authority. Never lossy-normalize or hash a
/// legacy identifier: an incompatible value must stop the required endpoint
/// before token/socket/sidecar creation instead of silently becoming no
/// subject. Disabled CC preserves the daemon's historical operator-id grammar.
#[cfg(any(unix, windows))]
pub(crate) fn daemon_subject_from_operator_id(
    operator_id: Option<&str>,
    required: bool,
) -> Result<Option<SubjectId>> {
    match operator_id {
        Some(value) if required => SubjectId::new(value).map(Some).map_err(|_| {
            anyhow::anyhow!("connector-control operator_id is incompatible with SubjectId")
        }),
        None if required => {
            bail!("connector-control requires an operator_id compatible with SubjectId")
        }
        _ => Ok(None),
    }
}

#[cfg(unix)]
fn bind_endpoint(home: &Path, endpoint_nonce: &str) -> Result<Endpoint> {
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    bail!("connector-control RPC has no kernel peer-credential proof on this Unix platform");

    let endpoint = endpoint_for_home(home, endpoint_nonce)?;
    // Persist the exact random root before creating it. This closes the crash
    // window between socket bind and sidecar publication without ever scanning
    // attacker-controlled entries under sticky `/tmp` on restart.
    write_prebind(home, &endpoint)?;
    if let Err(error) = ensure_endpoint_directories(&endpoint) {
        if let Err(cleanup_error) = remove_endpoint_socket_and_empty_ancestors(home, &endpoint) {
            return Err(cleanup_error).context(
                "retain connector-control pre-bind journal after partial bind cleanup failure",
            );
        }
        remove_prebind_checked(home)?;
        return Err(error);
    }
    Ok(endpoint)
}

/// Derive the sole accepted connector-control endpoint without touching the
/// filesystem. Both the canonical home and the domain-separated endpoint nonce
/// are bound into the compact channel namespace and basename.
#[cfg(unix)]
fn endpoint_for_home(home: &Path, endpoint_nonce: &str) -> Result<Endpoint> {
    validate_nonce(endpoint_nonce)?;
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let runtime_nonce = random_runtime_nonce()?;
    endpoint_for_home_hash(
        &canonical_home_sha256(&canonical_home),
        endpoint_nonce,
        &runtime_nonce,
    )
}

#[cfg(unix)]
fn canonical_home_sha256(home: &Path) -> String {
    hex::encode(Sha256::digest(home.as_os_str().as_encoded_bytes()))
}

#[cfg(unix)]
fn endpoint_for_home_with_runtime_nonce(
    home: &Path,
    endpoint_nonce: &str,
    runtime_nonce: &str,
) -> Result<Endpoint> {
    validate_nonce(endpoint_nonce)?;
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    endpoint_for_home_hash(
        &canonical_home_sha256(&canonical_home),
        endpoint_nonce,
        runtime_nonce,
    )
}

#[cfg(unix)]
fn endpoint_for_home_hash(
    home_sha256: &str,
    endpoint_nonce: &str,
    runtime_nonce: &str,
) -> Result<Endpoint> {
    validate_home_sha256(home_sha256)?;
    validate_nonce(endpoint_nonce)?;
    validate_nonce(runtime_nonce)?;
    let mut channel_hash = Sha256::new();
    channel_hash.update(b"neoth-connector-control-rpc-v1-unix-socket\0");
    channel_hash.update(home_sha256.as_bytes());
    channel_hash.update([0]);
    channel_hash.update(endpoint_nonce.as_bytes());
    let path = private_runtime_root(runtime_nonce)?
        .join(home_namespace_name(home_sha256))
        .join(channel_namespace_name(&hex::encode(
            channel_hash.finalize(),
        )))
        .join(SOCKET_BASENAME);
    ensure!(
        path.as_os_str().as_encoded_bytes().len() < MAX_UNIX_SOCKET_PATH_BYTES,
        "connector-control socket path exceeds AF_UNIX cap"
    );
    Ok(Endpoint::UnixSocket {
        path,
        endpoint_nonce: endpoint_nonce.to_owned(),
        home_sha256: home_sha256.to_owned(),
        runtime_nonce: runtime_nonce.to_owned(),
    })
}

#[cfg(unix)]
fn random_runtime_nonce() -> Result<String> {
    let mut raw = [0_u8; 16];
    getrandom::getrandom(&mut raw)
        .context("OS RNG unavailable for connector-control runtime namespace")?;
    Ok(hex::encode(raw))
}

#[cfg(unix)]
fn private_runtime_root(runtime_nonce: &str) -> Result<PathBuf> {
    validate_nonce(runtime_nonce)?;
    // macOS commonly exposes `/tmp` as a symlink to `/private/tmp`. Resolve
    // that system alias once, validate the real sticky/private parent, and
    // retain the resolved spelling for every exact endpoint comparison.
    let parent = std::fs::canonicalize(Path::new("/tmp"))
        .context("canonicalize connector-control system temporary directory")?;
    validate_safe_fallback_parent(&parent)?;
    Ok(parent.join(format!("{RUNTIME_ROOT_PREFIX}{runtime_nonce}")))
}

#[cfg(unix)]
fn home_namespace_name(home_sha256: &str) -> String {
    format!(
        "{HOME_NAMESPACE_PREFIX}{}",
        &home_sha256[..HOME_NAMESPACE_HEX_LEN]
    )
}

#[cfg(unix)]
fn channel_namespace_name(channel_hash: &str) -> String {
    format!(
        "{CHANNEL_NAMESPACE_PREFIX}{}",
        &channel_hash[..CHANNEL_NAMESPACE_HEX_LEN]
    )
}

#[cfg(unix)]
fn ensure_endpoint_directories(endpoint: &Endpoint) -> Result<()> {
    let Endpoint::UnixSocket {
        path,
        endpoint_nonce,
        home_sha256,
        runtime_nonce,
    } = endpoint;
    let expected = endpoint_for_home_hash(home_sha256, endpoint_nonce, runtime_nonce)?;
    ensure!(
        endpoint == &expected,
        "connector-control endpoint directories require the exact canonical endpoint"
    );
    let channel_root = path
        .parent()
        .context("connector-control endpoint has no channel namespace")?;
    let home_root = channel_root
        .parent()
        .context("connector-control endpoint has no home namespace")?;
    let runtime_root = home_root
        .parent()
        .context("connector-control endpoint has no runtime root")?;
    ensure_private_socket_directory(runtime_root, "connector-control RPC runtime root")?;
    ensure_private_socket_directory(home_root, "connector-control RPC home namespace")?;
    ensure_private_socket_directory(channel_root, "connector-control RPC channel namespace")
}

#[cfg(unix)]
fn validate_private_runtime_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect private {label} {}", path.display()))?;
    ensure!(
        private_directory_metadata_matches_owner(&metadata, unsafe { libc::geteuid() }),
        "{label} is not current-user private"
    );
    Ok(())
}

#[cfg(unix)]
fn private_directory_metadata_matches_owner(metadata: &std::fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == owner
        && metadata.mode() & 0o077 == 0
}

#[cfg(unix)]
fn validate_safe_fallback_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspect connector-control fallback parent {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "connector-control fallback runtime parent is not a real directory"
    );
    let mode = metadata.mode();
    let current_uid = unsafe { libc::geteuid() };
    let private_current_user = metadata.uid() == current_uid && mode & 0o077 == 0;
    let sticky_root_tmp = metadata.uid() == 0 && mode & 0o1000 != 0;
    ensure!(
        private_current_user || sticky_root_tmp,
        "connector-control fallback runtime parent is not trusted"
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_private_socket_directory(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    if !path.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create private {label} {}", path.display()))?;
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        private_directory_metadata_matches_owner(&metadata, unsafe { libc::geteuid() }),
        "{label} is not current-user private"
    );
    Ok(())
}

#[cfg(unix)]
fn bind_listener(endpoint: &Endpoint) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let Endpoint::UnixSocket { path, .. } = endpoint;
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind connector-control RPC socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// An internal accept failure is an authority-boundary failure, not a normal
/// listener exit. Close admission before removing discoverability so an
/// already accepted handler cannot start a new SQLite/WAL effect while its
/// parent task drains the previously owned JoinSet.
#[cfg(unix)]
fn withdraw_after_listener_failure(
    home: &Path,
    shutdown: &RpcShutdown,
    endpoint: Option<Endpoint>,
) -> Result<()> {
    shutdown.stop();
    if let Some(endpoint) = endpoint {
        remove_endpoint_socket_and_empty_ancestors(home, &endpoint)?;
        remove_sidecar_checked(home)?;
        remove_prebind_checked(home)?;
    }
    remove_boot_artifacts(home, None);
    Ok(())
}

#[cfg(unix)]
async fn run_listener(
    listener: tokio::net::UnixListener,
    endpoint: Endpoint,
    state: Arc<RpcState>,
    shutdown: Arc<RpcShutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections = JoinSet::new();
    let listener_failure = loop {
        let accepted = if connections.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break None,
                accepted = listener.accept() => accepted.map_err(anyhow::Error::from),
            }
        } else {
            tokio::select! {
                _ = shutdown.cancelled() => break None,
                joined = connections.join_next() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(
                            %error,
                            "connector-control RPC owned connection task failed"
                        );
                    }
                    continue;
                }
                accepted = listener.accept() => accepted.map_err(anyhow::Error::from),
            }
        };
        let (stream, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => break Some(error.context("accept connector-control RPC connection")),
        };
        if shutdown.is_stopped() {
            drop(stream);
            break None;
        }
        if !same_effective_uid(&stream) {
            drop(stream);
            continue;
        }
        let permit = match Arc::clone(&limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(stream);
                continue;
            }
        };
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, state, shutdown).await {
                tracing::warn!(%error, "connector-control RPC connection failed");
            }
        });
    };
    // The listener is no longer needed after an accept-loop exit. On an
    // internal failure, close the fd before withdrawing its filesystem leaf.
    drop(listener);
    let withdrawal_error = listener_failure
        .is_some()
        .then(|| withdraw_after_listener_failure(&state.home, &shutdown, Some(endpoint)))
        .transpose()
        .err();
    // An effect that passed its pre-admission deadline is now daemon-owned.
    // Do not abort the JoinSet: every blocking SQLite/WAL call remains joined
    // until terminal completion, including after client disconnect or endpoint
    // withdrawal. This retains the concurrency permit for its full lifetime.
    while let Some(joined) = connections.join_next().await {
        if let Err(error) = joined {
            tracing::warn!(%error, "connector-control RPC owned connection task panicked");
        }
    }
    if let Some(error) = withdrawal_error {
        return Err(error.context("withdraw connector-control listener after accept failure"));
    }
    match listener_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Windows acceptance is already current-TokenUser-attested by
/// `windows_private_ipc::Listener::accept`. Keep every admitted connection in
/// this JoinSet through its terminal SQLite/WAL result before the listener is
/// torn down, so VFS-backed ContextStore owners drop before pipe shutdown.
#[cfg(windows)]
async fn run_windows_listener(
    mut listener: crate::windows_private_ipc::Listener,
    state: Arc<RpcState>,
    shutdown: Arc<RpcShutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections = JoinSet::new();
    let listener_failure = loop {
        let accepted = if connections.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break None,
                accepted = listener.accept() => accepted,
            }
        } else {
            tokio::select! {
                _ = shutdown.cancelled() => break None,
                joined = connections.join_next() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(%error, "connector-control RPC owned connection task failed");
                    }
                    continue;
                }
                accepted = listener.accept() => accepted,
            }
        };
        let stream = match accepted {
            Ok(stream) => stream,
            Err(error) => {
                break Some(error.context("accept connector-control named-pipe connection"));
            }
        };
        if shutdown.is_stopped() {
            drop(stream);
            break None;
        }
        let permit = match Arc::clone(&limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(stream);
                continue;
            }
        };
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, state, shutdown).await {
                tracing::warn!(%error, "connector-control named-pipe connection failed");
            }
        });
    };
    drop(listener);
    while let Some(joined) = connections.join_next().await {
        if let Err(error) = joined {
            tracing::warn!(%error, "connector-control named-pipe connection task panicked");
        }
    }
    match listener_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn same_effective_uid(stream: &tokio::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd as _;
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credential` is a valid output buffer and the socket fd is live.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        )
    };
    result == 0
        && length as usize == std::mem::size_of::<libc::ucred>()
        && unsafe { credential.assume_init().uid } == unsafe { libc::geteuid() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn same_effective_uid(stream: &tokio::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd as _;
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: `stream` owns a live connected Unix-domain socket and the two
    // scalar output pointers are valid for getpeereid to initialize.
    (unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 })
        && uid == unsafe { libc::geteuid() }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn same_effective_uid(_: &tokio::net::UnixStream) -> bool {
    // Unsupported peer credential API: do not publish a weaker identity
    // boundary under some other Unix transport.
    false
}

#[cfg(any(unix, windows))]
async fn handle_connection<S>(
    mut stream: S,
    state: Arc<RpcState>,
    shutdown: Arc<RpcShutdown>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let deadline = Instant::now()
        .checked_add(CONNECTION_TIMEOUT)
        .context("connector-control connection deadline overflow")?;
    let Some(request) = tokio::time::timeout(CONNECTION_TIMEOUT, read_request(&mut stream))
        .await
        .ok()
        .flatten()
    else {
        write_response(&mut stream, 400, "bad_request", None).await?;
        return Ok(());
    };
    let route = request.path.split('?').next().unwrap_or_default();
    if request.method != "POST"
        || !matches!(
            route,
            "/cc/health"
                | "/cc/accounts/status"
                | "/cc/local-import/plan"
                | "/cc/local-import/apply"
                | "/cc/local-import/pause"
                | "/cc/local-import/resume"
        )
    {
        write_response(&mut stream, 404, "not_found", None).await?;
        return Ok(());
    }
    let source = "same-user-connector-control-ipc";
    let now = Instant::now();
    let authenticated = request
        .bearer
        .as_deref()
        .is_some_and(|candidate| constant_time_token_eq(candidate, &state.token));
    if !authenticated {
        let code = if state.cooldown.is_locked(source, now) {
            "cooldown"
        } else {
            state.cooldown.record_failure(source, now);
            "unauthorized"
        };
        write_response(
            &mut stream,
            if code == "cooldown" { 429 } else { 401 },
            code,
            None,
        )
        .await?;
        return Ok(());
    }
    state.cooldown.record_success(source);
    if Instant::now() >= deadline {
        write_response(&mut stream, 408, "deadline_exceeded_before_admission", None).await?;
        return Ok(());
    }
    let route = route.to_owned();
    let body = request.body;
    let state_for_work = Arc::clone(&state);
    // The connection task owns this JoinHandle. It is never raced against a
    // timeout or discarded; once started, an apply's one-shot confirmation is
    // a daemon responsibility and this task remains in run_listener's JoinSet
    // until its terminal SQLite/WAL result is observed.
    let Some(work) = shutdown.admit_blocking(|| {
        tokio::task::spawn_blocking(move || process_route(&route, &body, &state_for_work))
    }) else {
        write_response(&mut stream, 503, "shutting_down", None).await?;
        return Ok(());
    };
    let result = work
        .await
        .map_err(|_| anyhow::anyhow!("connector-control RPC worker panicked"))?;
    match result {
        Ok(value) => write_response(&mut stream, 200, "ok", value.as_deref()).await?,
        Err(code) => write_response(&mut stream, 422, code, None).await?,
    }
    Ok(())
}

#[cfg(any(unix, windows))]
struct ParsedRequest {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
}

#[cfg(any(unix, windows))]
async fn read_request<S>(stream: &mut S) -> Option<ParsedRequest>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if buf.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(index) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&buf[..header_end - 4]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    if request_line.next()? != "HTTP/1.1" || request_line.next().is_some() {
        return None;
    }
    let mut bearer = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("authorization") {
            if bearer.is_some() {
                return None;
            }
            bearer = extract_bearer_token(value.trim()).map(str::to_owned);
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return None;
            }
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    let content_length = content_length?;
    if content_length > MAX_BODY_BYTES
        || header_end.checked_add(content_length)? > MAX_REQUEST_BYTES
    {
        return None;
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > content_length {
            return None;
        }
    }
    (body.len() == content_length).then_some(ParsedRequest {
        method,
        path,
        bearer,
        body,
    })
}

#[cfg(any(unix, windows))]
async fn write_response<S>(
    stream: &mut S,
    status: u16,
    code: &str,
    data: Option<&str>,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let body = match data {
        Some(data) => format!("{{\"ok\":true,\"data\":{data}}}"),
        None => format!("{{\"ok\":{},\"code\":\"{code}\"}}", status == 200),
    };
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "connector-control response exceeds cap"
    );
    let response = format!(
        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        http_status_line(status),
        body.len()
    );
    // Socket output is not an authority effect. A peer that stops reading
    // cannot retain an owned operation/connection permit past this same
    // bounded response deadline after the terminal worker already joined.
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await
    .context("connector-control response deadline exceeded")??;
    Ok(())
}

#[cfg(any(unix, windows))]
fn http_status_line(status: u16) -> &'static str {
    match status {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        401 => "HTTP/1.1 401 Unauthorized",
        404 => "HTTP/1.1 404 Not Found",
        408 => "HTTP/1.1 408 Request Timeout",
        422 => "HTTP/1.1 422 Unprocessable Content",
        429 => "HTTP/1.1 429 Too Many Requests",
        503 => "HTTP/1.1 503 Service Unavailable",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

#[cfg(any(unix, windows))]
fn process_route(
    route: &str,
    body: &[u8],
    state: &RpcState,
) -> std::result::Result<Option<String>, &'static str> {
    match route {
        "/cc/health" if body.is_empty() => Ok(Some(
            "{\"ready\":true,\"transport\":\"same_user_os_ipc\"}".to_owned(),
        )),
        "/cc/health" => Err("health_request_must_be_empty"),
        "/cc/accounts/status" => {
            if !body.is_empty() {
                return Err("accounts_status_request_must_be_empty");
            }
            let accounts = state.plane.status().map_err(|_| "authority_unavailable")?;
            encode_accounts_status(&accounts)
                .map(Some)
                .map_err(|_| "response_encode_failed")
        }
        "/cc/local-import/plan" => {
            let request: PlanRequest =
                serde_json::from_slice(body).map_err(|_| "invalid_plan_request")?;
            let plan = plan_import(state, request).map_err(|_| "local_import_unavailable")?;
            Ok(Some(plan))
        }
        "/cc/local-import/apply" => {
            let request: ApplyRequest =
                serde_json::from_slice(body).map_err(|_| "invalid_apply_request")?;
            let outcome = apply_import(state, request).map_err(|_| "local_import_apply_failed")?;
            Ok(Some(outcome))
        }
        "/cc/local-import/pause" => {
            let request: LifecycleRequest =
                serde_json::from_slice(body).map_err(|_| "invalid_lifecycle_request")?;
            let outcome = transition_lifecycle(state, request, ConnectorLifecycle::Paused)
                .map_err(|_| "local_import_lifecycle_failed")?;
            Ok(Some(outcome))
        }
        "/cc/local-import/resume" => {
            let request: LifecycleRequest =
                serde_json::from_slice(body).map_err(|_| "invalid_lifecycle_request")?;
            let outcome = transition_lifecycle(state, request, ConnectorLifecycle::Active)
                .map_err(|_| "local_import_lifecycle_failed")?;
            Ok(Some(outcome))
        }
        _ => Err("not_found"),
    }
}

#[cfg(any(unix, windows))]
fn transition_lifecycle(
    state: &RpcState,
    request: LifecycleRequest,
    target: ConnectorLifecycle,
) -> Result<String> {
    let subject = state
        .daemon_subject
        .clone()
        .context("daemon has no configured connector-control subject")?;
    let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
    let (current, next) = state.plane.prepare_lifecycle_successor(
        &daemon_authenticated_session(subject),
        &instance,
        request.policy_revision,
        request.lifecycle_revision,
        target,
    )?;
    let response_account = next
        .account(&instance)
        .cloned()
        .context("prepared local-import lifecycle is absent from its successor")?;
    let next_for_config = next.clone();
    let (update, ()) =
        crate::config::FreedomConfig::prepare_update_at(&state.config_path, move |config| {
            ensure!(
                config.context_connectors == current,
                "freedom.yaml connector-control state differs from the live daemon projection"
            );
            config.context_connectors = next_for_config;
            Ok(())
        })?;
    let deadline = Instant::now()
        .checked_add(CONNECTION_TIMEOUT)
        .context("connector lifecycle drain deadline overflow")?;
    let transition = state.plane.begin_lifecycle_transition(next, deadline)?;
    if Instant::now() >= deadline {
        // The transition is still unpublished; dropping it restores its
        // captured admission state without reporting an unapplied timeout as
        // a committed lifecycle mutation.
        drop(transition);
        bail!("connector lifecycle deadline elapsed before durable publication");
    }
    transition.commit_durable_update(update)?;
    let encoded = serde_json::to_string(&serde_json::json!({
        "connector": response_account.configuration.connector_id.as_str(),
        "lifecycle": format!("{:?}", response_account.lifecycle).to_lowercase(),
        "policy_revision": response_account.configuration.policy.revision,
        "lifecycle_revision": response_account.lifecycle_revision,
    }))?;
    ensure!(
        encoded.len() <= MAX_RESPONSE_BYTES,
        "connector-control lifecycle response exceeds response cap"
    );
    Ok(encoded)
}

#[cfg(any(unix, windows))]
fn encode_accounts_status(accounts: &[super::ConnectorAccountStatus]) -> Result<String> {
    let views = accounts
        .iter()
        .map(|account| {
            serde_json::json!({
                "connector": account.instance_id.connector_id.as_str(),
                "lifecycle": format!("{:?}", account.lifecycle).to_lowercase(),
                "policy_revision": account.policy_revision,
                "lifecycle_revision": account.lifecycle_revision,
            })
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_string(&serde_json::json!({"accounts": views}))?;
    ensure!(
        encoded.len() <= MAX_RESPONSE_BYTES,
        "connector-control accounts status exceeds response cap"
    );
    Ok(encoded)
}

#[cfg(any(unix, windows))]
fn plan_import(state: &RpcState, request: PlanRequest) -> Result<String> {
    release_expired_pending_plans(state)?;
    let plan_id = random_opaque()?;
    let confirmation_nonce = random_opaque()?;
    let apply_key = context_import_apply_key(&plan_id, &confirmation_nonce)?;
    let expires_at = Instant::now()
        .checked_add(PLAN_TTL)
        .context("plan TTL overflow")?;
    reserve_planning_slot(state, &plan_id, expires_at)?;

    let pending = match build_pending_plan(
        state,
        request,
        &apply_key,
        confirmation_nonce.clone(),
        expires_at,
    ) {
        Ok(pending) => pending,
        Err(error) => {
            let _ = remove_planning_slot(state, &plan_id);
            return Err(error);
        }
    };
    let mut registry = match state.plans.lock() {
        Ok(registry) => registry,
        Err(_) => {
            let mut runtime = pending.runtime;
            let release = runtime.release_apply_outcome(&apply_key);
            return match release {
                Ok(()) => Err(anyhow::anyhow!("plan registry poisoned")),
                Err(release_error) => Err(anyhow::anyhow!(
                    "plan registry poisoned; failed to release context-import admission: {release_error:#}"
                )),
            };
        }
    };
    if registry.planning.remove(&plan_id).is_none() {
        drop(registry);
        let mut runtime = pending.runtime;
        runtime.release_apply_outcome(&apply_key)?;
        bail!("plan admission expired before publication");
    }
    let collided = match registry.pending.entry(plan_id.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(pending);
            None
        }
        std::collections::btree_map::Entry::Occupied(_) => Some(pending),
    };
    if let Some(pending) = collided {
        drop(registry);
        let mut runtime = pending.runtime;
        runtime.release_apply_outcome(&apply_key)?;
        bail!("opaque plan identity collided during publication");
    }
    Ok(serde_json::json!({
        "plan_id": plan_id,
        "confirmation_nonce": confirmation_nonce,
    })
    .to_string())
}

#[cfg(any(unix, windows))]
fn build_pending_plan(
    state: &RpcState,
    request: PlanRequest,
    apply_key: &ContextImportApplyKey,
    confirmation_nonce: String,
    expires_at: Instant,
) -> Result<PendingPlan> {
    let subject = state
        .daemon_subject
        .clone()
        .context("daemon has no configured connector-control subject")?;
    let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
    let authority = state
        .plane
        .authorize_context_import(&daemon_authenticated_session(subject), &instance)?;
    let binding = authority.acquire_context_import_runtime()?;
    let root = approve_import_root(Path::new(&request.root))?;
    let mut plan_key = [0u8; 32];
    getrandom::getrandom(&mut plan_key)?;
    let capability = issue_operator_import_capability(root, plan_key, binding.capability_binding());
    let key = crate::wal::master_key::load_existing_master_key_at(&state.home)?;
    let store = ContextStore::open_at(state.home.join("context.db"), &key)?;
    let mut runtime = RuntimeLocalImport::new(capability, binding, store)?;
    let reservation = runtime.reserve_apply_outcome(apply_key)?;
    ensure!(
        !reservation.accepted(),
        "fresh opaque plan identity unexpectedly names a committed outcome"
    );
    let local_plan_id = match runtime.plan_import(Path::new(&request.relative_path)) {
        Ok(plan_id) => plan_id,
        Err(error) => {
            if let Err(release_error) = runtime.release_apply_outcome(apply_key) {
                return Err(anyhow::anyhow!(
                    "{error:#}; failed to release context-import admission: {release_error:#}"
                ));
            }
            return Err(error);
        }
    };
    Ok(PendingPlan {
        runtime,
        local_plan_id,
        confirmation_nonce,
        expires_at,
    })
}

#[cfg(any(unix, windows))]
fn apply_import(state: &RpcState, request: ApplyRequest) -> Result<String> {
    release_expired_pending_plans(state)?;
    {
        let registry = state
            .plans
            .lock()
            .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?;
        if let Some(pending) = registry.pending.get(&request.plan_id) {
            // Authenticate the in-memory plan before querying durable state or
            // consuming it. A wrong nonce cannot poison the real reservation.
            ensure!(
                constant_time_token_eq(&request.confirmation_nonce, &pending.confirmation_nonce,),
                "confirmation nonce does not match plan"
            );
        }
    }
    let apply_key = context_import_apply_key(&request.plan_id, &request.confirmation_nonce)?;
    let recovery = context_evidence_replay_runtime(state)?;
    let durable = recovery.query_apply_outcome(&apply_key)?;
    if let Some(outcome) = durable.filter(|outcome| outcome.accepted()) {
        let mut registry = state
            .plans
            .lock()
            .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?;
        registry.pending.remove(&request.plan_id);
        return Ok(plan_outcome_response(outcome.audit_pending()));
    }
    let mut pending = {
        let mut registry = state
            .plans
            .lock()
            .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?;
        if let Some(pending) = registry.pending.get(&request.plan_id) {
            ensure!(
                constant_time_token_eq(&request.confirmation_nonce, &pending.confirmation_nonce,),
                "confirmation nonce does not match plan"
            );
        }
        let pending = registry.pending.remove(&request.plan_id);
        if pending.is_none() {
            ensure!(
                durable.is_none(),
                "plan apply is already in progress or unavailable"
            );
        }
        pending.context("plan absent, expired, or consumed")?
    };
    let outcome = pending.runtime.confirm_import_with_outcome(
        pending.local_plan_id,
        pending.local_plan_id,
        &apply_key,
    )?;
    ensure!(
        outcome.accepted(),
        "context-import commit did not persist acceptance"
    );
    let mut sink = DaemonWalSink {
        writer: state.writer.clone(),
    };
    let audit_pending = pending.runtime.replay_receipts(&mut sink).is_err();
    Ok(plan_outcome_response(audit_pending))
}

#[cfg(any(unix, windows))]
fn reserve_planning_slot(state: &RpcState, plan_id: &str, expires_at: Instant) -> Result<()> {
    let mut registry = state
        .plans
        .lock()
        .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?;
    reserve_planning_slot_in_registry(&mut registry, plan_id, expires_at, Instant::now())
}

#[cfg(any(unix, windows))]
fn reserve_planning_slot_in_registry(
    registry: &mut PlanRegistry,
    plan_id: &str,
    expires_at: Instant,
    now: Instant,
) -> Result<()> {
    registry.planning.retain(|_, deadline| *deadline > now);
    ensure!(
        registry
            .planning
            .len()
            .saturating_add(registry.pending.len())
            < MAX_PENDING_PLANS,
        "plan retention cap reached"
    );
    ensure!(
        registry
            .planning
            .insert(plan_id.to_owned(), expires_at)
            .is_none(),
        "opaque plan identity collided during admission"
    );
    Ok(())
}

#[cfg(any(unix, windows))]
fn remove_planning_slot(state: &RpcState, plan_id: &str) -> Result<()> {
    state
        .plans
        .lock()
        .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?
        .planning
        .remove(plan_id);
    Ok(())
}

#[cfg(any(unix, windows))]
fn release_expired_pending_plans(state: &RpcState) -> Result<()> {
    loop {
        let expired = {
            let mut registry = state
                .plans
                .lock()
                .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?;
            let now = Instant::now();
            registry.planning.retain(|_, deadline| *deadline > now);
            let plan_id = registry.pending.iter().find_map(|(plan_id, pending)| {
                (pending.expires_at <= now).then(|| plan_id.clone())
            });
            plan_id.and_then(|plan_id| {
                registry
                    .pending
                    .remove(&plan_id)
                    .map(|pending| (plan_id, pending))
            })
        };
        let Some((plan_id, mut pending)) = expired else {
            return Ok(());
        };
        let apply_key = match context_import_apply_key(&plan_id, &pending.confirmation_nonce) {
            Ok(key) => key,
            Err(error) => {
                state
                    .plans
                    .lock()
                    .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?
                    .pending
                    .insert(plan_id, pending);
                return Err(error);
            }
        };
        if let Err(error) = pending.runtime.release_apply_outcome(&apply_key) {
            state
                .plans
                .lock()
                .map_err(|_| anyhow::anyhow!("plan registry poisoned"))?
                .pending
                .insert(plan_id, pending);
            return Err(error);
        }
    }
}

#[cfg(any(unix, windows))]
fn context_evidence_replay_runtime(state: &RpcState) -> Result<ContextEvidenceReplayRuntime> {
    let subject = state
        .daemon_subject
        .clone()
        .context("daemon has no configured connector-control subject")?;
    let instance = ConnectorInstanceId::accountless(ConnectorId::LocalImport);
    let authority = state
        .plane
        .authorize_context_import(&daemon_authenticated_session(subject), &instance)?;
    let binding = authority.acquire_context_import_runtime()?;
    let key = crate::wal::master_key::load_existing_master_key_at(&state.home)?;
    let store = ContextStore::open_at(state.home.join("context.db"), &key)?;
    Ok(ContextEvidenceReplayRuntime::new(binding, store))
}

#[cfg(any(unix, windows))]
fn context_import_apply_key(
    plan_id: &str,
    confirmation_nonce: &str,
) -> Result<ContextImportApplyKey> {
    Ok(ContextImportApplyKey::new(
        decode_lower_hex_32("plan id", plan_id)?,
        decode_lower_hex_32("confirmation nonce", confirmation_nonce)?,
    ))
}

#[cfg(any(unix, windows))]
fn decode_lower_hex_32(label: &str, value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64,
        "{label} must contain exactly 64 lowercase hex bytes"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must contain exactly 64 lowercase hex bytes"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must decode to exactly 32 bytes"))
}

#[cfg(any(unix, windows))]
fn plan_outcome_response(audit_pending: bool) -> String {
    serde_json::json!({"accepted": true, "audit_pending": audit_pending}).to_string()
}

#[cfg(any(unix, windows))]
struct DaemonWalSink {
    writer: WalWriterHandle,
}

#[cfg(any(unix, windows))]
impl ContextEvidenceWalSink for DaemonWalSink {
    fn append_context_evidence_receipt_once(
        &mut self,
        receipt_handle: &[u8; 32],
        receipt: ContextEvidenceReceipt,
    ) -> Result<()> {
        // This runs only inside the listener-owned `spawn_blocking` worker.
        // The WAL writer retains its capability-bound receipt authority through
        // strict authenticated history scan and missing-frame append, so a
        // post-append/pre-ACK retry is an idempotent success rather than a
        // duplicated security-sensitive evidence frame.
        self.writer
            .append_context_evidence_receipt_once_blocking(receipt_handle, receipt)
    }
}

#[cfg(any(unix, windows, test))]
fn random_opaque() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::connectors::{
        control_plane::ConnectorAccountStatus, control_state::ConnectorLifecycle,
    };
    /// Test-only endpoint nonces still exercise the production parser and
    /// endpoint derivation, but must not resemble reusable cryptographic
    /// material in the compiled test binary.
    #[cfg(any(unix, windows))]
    fn fresh_test_nonce() -> String {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).expect("OS randomness for connector-control test nonce");
        hex::encode(bytes)
    }

    #[cfg(unix)]
    fn different_test_nonce(nonce: &str) -> String {
        let mut bytes = nonce.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("hex test nonce remains UTF-8")
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_response_parser_rejects_ambiguous_and_truncated_envelopes() {
        assert!(
            validate_unix_success_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            )
            .is_ok()
        );
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n{}".as_slice(),
        ] {
            assert!(
                validate_unix_success_response(response).is_err(),
                "ambiguous or incomplete connector-control response must fail closed"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn connector_nonce_is_strict_and_domain_separated_from_pid_nonce() {
        let audit_nonce = fresh_test_nonce();
        let connector = connector_nonce(&audit_nonce);
        assert_eq!(connector.len(), 32);
        assert!(
            connector
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(connector, audit_nonce);
        assert!(validate_nonce(&connector).is_ok());
        let mut uppercase = audit_nonce.clone().into_bytes();
        uppercase[0] = b'A';
        let uppercase = String::from_utf8(uppercase).expect("hex test nonce remains UTF-8");
        assert!(validate_nonce(&uppercase).is_err());
        assert!(validate_nonce(&audit_nonce[..audit_nonce.len() - 1]).is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn lifecycle_request_requires_exact_revision_fields() {
        assert!(
            serde_json::from_slice::<LifecycleRequest>(
                br#"{"policy_revision":7,"lifecycle_revision":11}"#,
            )
            .is_ok()
        );
        for body in [
            br#"{}"#.as_slice(),
            br#"{"policy_revision":7}"#.as_slice(),
            br#"{"policy_revision":7,"lifecycle_revision":11,"account":"other"}"#.as_slice(),
            br#"{"policy_revision":-1,"lifecycle_revision":11}"#.as_slice(),
        ] {
            assert!(
                serde_json::from_slice::<LifecycleRequest>(body).is_err(),
                "malformed lifecycle request must not reach transition admission"
            );
        }
    }

    #[test]
    fn opaque_plan_and_confirmation_values_are_fresh_fixed_width_handles() {
        let plan = random_opaque().unwrap();
        let confirmation = random_opaque().unwrap();
        assert_eq!(plan.len(), 64);
        assert_eq!(confirmation.len(), 64);
        assert_ne!(plan, confirmation);
        assert!(
            plan.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_connector_control_pipe_namespace_is_distinct_from_audit() {
        let home_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let audit_nonce = fresh_test_nonce();
        let connector_nonce = connector_nonce(&audit_nonce);
        let connector = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
            "neoth-cc-v1",
            home_sha256,
            &connector_nonce,
        )
        .unwrap();
        let audit = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
            "neoth-audit-v2",
            home_sha256,
            &audit_nonce,
        )
        .unwrap();
        assert_ne!(connector.name(), audit.name());
        assert!(
            connector
                .validate_binding("neoth-audit-v2", home_sha256, &connector_nonce)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_client_rejects_an_oversized_same_user_pipe_response_at_the_bound() {
        let endpoint = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
            "neoth-cc-response-bound-test",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            &fresh_test_nonce(),
        )
        .expect("test endpoint must derive");
        let mut listener =
            crate::windows_private_ipc::Listener::bind(endpoint.clone(), MAX_REQUEST_BYTES as u32)
                .expect("test listener must bind");
        let oversized = vec![b'x'; MAX_RESPONSE_ENVELOPE_BYTES + 1];
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await?;
            let request = read_request(&mut stream)
                .await
                .context("test client must send a complete request")?;
            assert_eq!(request.path, "/cc/health");
            stream.write_all(&oversized).await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        });
        let client = WindowsClient {
            endpoint,
            token: "test-cc-token".to_owned(),
        };
        let error = client
            .post("/cc/health", b"")
            .await
            .expect_err("client must reject response above its bounded envelope");
        assert!(
            error
                .to_string()
                .contains("connector-control client response envelope exceeds cap")
        );
        server
            .await
            .expect("oversized-response server task must not panic")
            .expect("oversized-response server must finish cleanly");
    }

    #[cfg(unix)]
    #[test]
    fn apply_identity_decoder_accepts_only_exact_lowercase_hex() {
        let valid = hex::encode([b'\n'; 32]);
        let uppercase = valid.to_uppercase();
        assert_ne!(
            valid, uppercase,
            "fixture must contain lowercase hex letters"
        );
        assert_eq!(decode_lower_hex_32("plan id", &valid).unwrap(), [b'\n'; 32]);
        assert!(decode_lower_hex_32("plan id", &uppercase).is_err());
        assert!(decode_lower_hex_32("plan id", &valid[..63]).is_err());
        assert!(decode_lower_hex_32("plan id", &format!("{valid}00")).is_err());
        assert!(decode_lower_hex_32("plan id", &"gg".repeat(32)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sixty_fifth_planning_slot_is_refused_before_runtime_or_store_work() {
        let now = Instant::now();
        let expires_at = now.checked_add(PLAN_TTL).unwrap();
        let mut registry = PlanRegistry {
            planning: BTreeMap::new(),
            pending: BTreeMap::new(),
        };
        for value in 0..MAX_PENDING_PLANS {
            reserve_planning_slot_in_registry(
                &mut registry,
                &format!("{value:064x}"),
                expires_at,
                now,
            )
            .unwrap();
        }
        assert!(
            reserve_planning_slot_in_registry(
                &mut registry,
                &format!("{:064x}", MAX_PENDING_PLANS),
                expires_at,
                now,
            )
            .is_err()
        );
        assert_eq!(registry.planning.len(), MAX_PENDING_PLANS);
        assert!(registry.pending.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn required_connector_control_rejects_legacy_incompatible_operator_id_before_artifacts() {
        assert_eq!(
            daemon_subject_from_operator_id(Some("lowercase"), true)
                .unwrap()
                .unwrap()
                .as_str(),
            "lowercase"
        );
        let home = crate::test_env::canonical_tempdir().unwrap();
        let error = daemon_subject_from_operator_id(Some("Alice"), true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("operator_id is incompatible with SubjectId")
        );
        let error = daemon_subject_from_operator_id(Some("dev-"), true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("operator_id is incompatible with SubjectId")
        );
        assert!(!home.path().join(TOKEN_FILE).exists());
        assert!(!home.path().join(SIDECAR_FILE).exists());
        // A disabled CC path preserves legacy daemon configuration unchanged.
        assert!(
            daemon_subject_from_operator_id(Some("dev-"), false)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_status_lines_are_valid_and_have_fixed_reason_phrases() {
        assert_eq!(http_status_line(200), "HTTP/1.1 200 OK");
        assert_eq!(http_status_line(422), "HTTP/1.1 422 Unprocessable Content");
        assert_eq!(http_status_line(999), "HTTP/1.1 500 Internal Server Error");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn response_uses_a_valid_http_status_line_with_reason_phrase() {
        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move {
            write_response(&mut server, 422, "invalid_plan_request", None).await
        });
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.unwrap();
        writer.await.unwrap().unwrap();
        assert!(
            std::str::from_utf8(&raw)
                .unwrap()
                .starts_with("HTTP/1.1 422 Unprocessable Content\r\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn current_max_connector_roster_status_is_canonical_and_below_response_cap() {
        let accounts = [
            ConnectorAccountStatus {
                instance_id: ConnectorInstanceId::accountless(ConnectorId::LocalImport),
                lifecycle: ConnectorLifecycle::Active,
                policy_revision: u64::MAX,
                lifecycle_revision: u64::MAX,
            },
            ConnectorAccountStatus {
                instance_id: ConnectorInstanceId::accountless(ConnectorId::Obsidian),
                lifecycle: ConnectorLifecycle::Revoked,
                policy_revision: u64::MAX,
                lifecycle_revision: u64::MAX,
            },
        ];
        let encoded = encode_accounts_status(&accounts).unwrap();
        assert!(encoded.len() <= MAX_RESPONSE_BYTES);
        assert!(encoded.contains("\"connector\":\"local_import\""));
        assert!(encoded.contains("\"connector\":\"obsidian\""));
        assert!(!encoded.contains("LocalImport"));
        assert!(!encoded.contains("Obsidian"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn parser_rejects_a_request_whose_header_plus_body_exceeds_the_total_cap() {
        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        let prefix = b"POST /cc/health HTTP/1.1\r\nContent-Length: 1\r\nX-Pad: ";
        let suffix = b"\r\n\r\n";
        let padding = vec![b'a'; MAX_REQUEST_BYTES - prefix.len() - suffix.len()];
        let mut request = Vec::with_capacity(MAX_REQUEST_BYTES + 1);
        request.extend_from_slice(prefix);
        request.extend_from_slice(&padding);
        request.extend_from_slice(suffix);
        request.push(b'x');
        let writer = tokio::spawn(async move {
            client.write_all(&request).await?;
            client.shutdown().await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), read_request(&mut server))
                .await
                .expect("over-cap request parser must finish within one second")
                .is_none()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), writer)
            .await
            .expect("over-cap request writer must finish within one second")
            .expect("over-cap request writer task must not panic")
            .expect("over-cap request writer must write and shut down");
    }

    #[tokio::test]
    async fn shutdown_signal_is_sticky_and_refuses_later_worker_admission() {
        let shutdown = RpcShutdown::new();
        shutdown.stop();
        tokio::time::timeout(std::time::Duration::from_millis(50), shutdown.cancelled())
            .await
            .expect("drop-time shutdown signal must not be lost");
        assert!(shutdown.is_stopped());
        assert!(
            shutdown
                .admit_blocking(|| tokio::task::spawn_blocking(|| ()))
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_stop_and_admit_has_one_linearized_winner() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering as AtomicOrdering},
            mpsc,
        };

        let shutdown = Arc::new(RpcShutdown::new());
        let release_start = Arc::new(Barrier::new(2));
        let started = Arc::new(AtomicBool::new(false));
        let runtime = tokio::runtime::Handle::current();
        let (start_entered_tx, start_entered_rx) = mpsc::channel();
        let admitting_shutdown = Arc::clone(&shutdown);
        let admitting_release_start = Arc::clone(&release_start);
        let admitting_started = Arc::clone(&started);
        let admitting = std::thread::spawn(move || {
            admitting_shutdown.admit_blocking(|| {
                start_entered_tx
                    .send(())
                    .expect("test receiver must await admission start");
                admitting_release_start.wait();
                runtime.spawn_blocking(move || {
                    admitting_started.store(true, AtomicOrdering::Release);
                })
            })
        });
        start_entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("admission must enter its worker-creation closure");

        let (stop_returned_tx, stop_returned_rx) = mpsc::channel();
        let stopping_shutdown = Arc::clone(&shutdown);
        let stopper = std::thread::spawn(move || {
            stopping_shutdown.stop();
            stop_returned_tx
                .send(())
                .expect("test receiver must await stop completion");
        });
        assert!(
            stop_returned_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "stop must not return while a pre-stop admission still creates its owned worker"
        );
        release_start.wait();

        let worker = admitting
            .join()
            .expect("admission contender must not panic")
            .expect("admission that entered before stop must create its owned worker");
        worker.await.expect("owned worker must finish");
        stop_returned_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("stop must return once worker creation released the admission lock");
        stopper.join().expect("stop contender must not panic");
        assert!(started.load(AtomicOrdering::Acquire));
        assert!(shutdown.is_stopped());
        assert!(
            shutdown
                .admit_blocking(|| tokio::task::spawn_blocking(|| ()))
                .is_none()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_failure_withdraws_discovery_before_preaccepted_work_can_admit_again() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering as AtomicOrdering},
            mpsc,
        };
        let home = crate::test_env::canonical_tempdir().unwrap();
        let token = home.path().join(TOKEN_FILE);
        let sidecar = home.path().join(SIDECAR_FILE);
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        let Endpoint::UnixSocket { path: socket, .. } = &endpoint;
        std::fs::write(&token, b"token").unwrap();
        write_sidecar(home.path(), &endpoint, &audit_nonce).unwrap();
        bind_fixture_socket(&endpoint);

        let shutdown = Arc::new(RpcShutdown::new());
        let release_start = Arc::new(Barrier::new(2));
        let started = Arc::new(AtomicBool::new(false));
        let runtime = tokio::runtime::Handle::current();
        let (start_entered_tx, start_entered_rx) = mpsc::channel();
        let admitting_shutdown = Arc::clone(&shutdown);
        let admitting_release_start = Arc::clone(&release_start);
        let admitting_started = Arc::clone(&started);
        let admitting = std::thread::spawn(move || {
            admitting_shutdown.admit_blocking(|| {
                start_entered_tx.send(()).unwrap();
                admitting_release_start.wait();
                runtime.spawn_blocking(move || {
                    admitting_started.store(true, AtomicOrdering::Release);
                })
            })
        });
        start_entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        let (withdrawn_tx, withdrawn_rx) = mpsc::channel();
        let failing_shutdown = Arc::clone(&shutdown);
        let failure_home = home.path().to_path_buf();
        let failure_endpoint = endpoint.clone();
        let failure = std::thread::spawn(move || {
            withdraw_after_listener_failure(
                &failure_home,
                &failing_shutdown,
                Some(failure_endpoint),
            )
            .unwrap();
            withdrawn_tx.send(()).unwrap();
        });
        assert!(
            withdrawn_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        assert!(sidecar.exists());

        release_start.wait();
        let worker = admitting.join().unwrap().unwrap();
        worker.await.unwrap();
        withdrawn_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        failure.join().unwrap();
        assert!(started.load(AtomicOrdering::Acquire));
        assert!(shutdown.is_stopped());
        assert!(!token.exists());
        assert!(!sidecar.exists());
        assert!(!socket.exists());
        assert!(
            shutdown
                .admit_blocking(|| tokio::task::spawn_blocking(|| ()))
                .is_none()
        );
    }

    #[test]
    fn stale_token_cleanup_is_scoped_to_the_cc_token_name() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let token = home.path().join(TOKEN_FILE);
        let unrelated = home.path().join("unrelated-token");
        std::fs::write(&token, b"stale-cc-token").unwrap();
        std::fs::write(&unrelated, b"preserve").unwrap();
        remove_boot_artifacts(home.path(), None);
        assert!(!token.exists());
        assert_eq!(std::fs::read(unrelated).unwrap(), b"preserve");
    }

    #[cfg(unix)]
    fn canonical_fixture(home: &Path, nonce: &str) -> Endpoint {
        let endpoint = endpoint_for_home(home, nonce).unwrap();
        ensure_endpoint_directories(&endpoint).unwrap();
        endpoint
    }

    #[cfg(unix)]
    fn bind_fixture_socket(endpoint: &Endpoint) {
        use std::os::unix::fs::PermissionsExt as _;

        let Endpoint::UnixSocket { path, .. } = endpoint;
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
    }

    #[cfg(unix)]
    fn write_fixture_sidecar(home: &Path, endpoint: &Endpoint, nonce: &str) {
        write_sidecar(home, endpoint, nonce).unwrap();
        std::fs::write(home.join(TOKEN_FILE), b"stale-token").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_discovery_rejects_wrong_cc_nonce_pid_lock_nonce_and_runtime_nonce_before_connect()
     {
        use crate::daemon::pidfile;

        // A sidecar that names any CC endpoint other than the one derived
        // from the live audit PID-lock nonce is rejected before token/socket
        // access. No listener is bound in this fixture.
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let cc_nonce = connector_nonce(&audit_nonce);
        let endpoint = canonical_fixture(home.path(), &cc_nonce);
        init_token(home.path()).unwrap();
        let mut guard = pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        guard.publish_endpoint_nonce(&audit_nonce).unwrap();
        write_sidecar(home.path(), &endpoint, &different_test_nonce(&cc_nonce)).unwrap();
        assert!(unix_client(home.path(), &audit_nonce).is_err());
        drop(guard);

        // A sidecar can carry the right derived CC nonce only while the exact
        // audit nonce is committed in the current PID-file lock.
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let cc_nonce = connector_nonce(&audit_nonce);
        let endpoint = canonical_fixture(home.path(), &cc_nonce);
        init_token(home.path()).unwrap();
        let mut guard = pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        guard
            .publish_endpoint_nonce(&different_test_nonce(&audit_nonce))
            .unwrap();
        write_sidecar(home.path(), &endpoint, &cc_nonce).unwrap();
        assert!(unix_client(home.path(), &audit_nonce).is_err());
        drop(guard);

        // The persisted runtime nonce is part of the endpoint derivation;
        // changing it cannot redirect a client to a different socket tree.
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let cc_nonce = connector_nonce(&audit_nonce);
        let endpoint = canonical_fixture(home.path(), &cc_nonce);
        let mut malformed = endpoint.clone();
        let Endpoint::UnixSocket { runtime_nonce, .. } = &mut malformed;
        *runtime_nonce = different_test_nonce(runtime_nonce);
        init_token(home.path()).unwrap();
        let mut guard = pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        guard.publish_endpoint_nonce(&audit_nonce).unwrap();
        write_sidecar(home.path(), &malformed, &cc_nonce).unwrap();
        assert!(unix_client(home.path(), &audit_nonce).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_discovery_rejects_group_readable_and_symlinked_tokens_before_connect() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let cc_nonce = connector_nonce(&audit_nonce);
        let endpoint = canonical_fixture(home.path(), &cc_nonce);
        let mut guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        guard.publish_endpoint_nonce(&audit_nonce).unwrap();
        write_sidecar(home.path(), &endpoint, &cc_nonce).unwrap();
        let token = home.path().join(TOKEN_FILE);
        std::fs::write(&token, b"test-token").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(unix_client(home.path(), &audit_nonce).is_err());

        std::fs::remove_file(&token).unwrap();
        let target = home.path().join("token-target");
        std::fs::write(&target, b"test-token").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &token).unwrap();
        assert!(unix_client(home.path(), &audit_nonce).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_discovery_reader_rejects_mode_symlink_and_oversize_on_the_opened_fd() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let home = crate::test_env::canonical_tempdir().unwrap();
        let bound = crate::skills::store::open_bound_directory(
            home.path(),
            false,
            "connector-control Unix reader test home",
        )
        .unwrap()
        .unwrap();
        let path = home.path().join("discovery");
        std::fs::write(&path, b"ok").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_unix_private_regular_file_bounded(
                &bound.dir,
                OsStr::new("discovery"),
                &path,
                MAX_RESPONSE_BYTES,
            )
            .unwrap(),
            b"ok"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            read_unix_private_regular_file_bounded(
                &bound.dir,
                OsStr::new("discovery"),
                &path,
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );

        std::fs::remove_file(&path).unwrap();
        let target = home.path().join("discovery-target");
        std::fs::write(&target, b"ok").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(
            read_unix_private_regular_file_bounded(
                &bound.dir,
                OsStr::new("discovery"),
                &path,
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_RESPONSE_BYTES + 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_unix_private_regular_file_bounded(
                &bound.dir,
                OsStr::new("discovery"),
                &path,
                MAX_RESPONSE_BYTES,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_endpoint_identity_detects_a_replaced_socket_leaf() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let endpoint = canonical_fixture(home.path(), &connector_nonce(&fresh_test_nonce()));
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        bind_fixture_socket(&endpoint);
        let before = verify_unix_client_endpoint(&endpoint).unwrap();
        std::fs::remove_file(path).unwrap();
        bind_fixture_socket(&endpoint);
        let after = verify_unix_client_endpoint(&endpoint).unwrap();
        assert_ne!(
            before, after,
            "a replaced socket leaf must change the attested identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_fixture_home_is_canonical_under_the_inherited_temp_environment() {
        // Environment is process-global. Hold the shared guard so this test
        // cannot race another fixture changing TMPDIR while macOS resolves
        // `/var` through `/private/var`.
        let _environment = crate::test_env::lock();
        let inherited_temp = std::env::temp_dir();
        let canonical_temp = std::fs::canonicalize(&inherited_temp).unwrap();
        let home = crate::test_env::canonical_tempdir().unwrap();
        assert_eq!(std::fs::canonicalize(home.path()).unwrap(), home.path());
        assert_eq!(home.path().parent(), Some(canonical_temp.as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_clean_shutdown_and_two_crash_restarts_remove_exact_prior_endpoint() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        for nonce in [fresh_test_nonce(), fresh_test_nonce(), fresh_test_nonce()] {
            let endpoint = canonical_fixture(home.path(), &nonce);
            let Endpoint::UnixSocket { path, .. } = &endpoint;
            bind_fixture_socket(&endpoint);
            write_fixture_sidecar(home.path(), &endpoint, &nonce);

            cleanup_prior_boot_artifacts(home.path()).unwrap();
            assert!(!home.path().join(TOKEN_FILE).exists());
            assert!(!home.path().join(SIDECAR_FILE).exists());
            assert!(!path.exists());
            assert!(!path.parent().unwrap().exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn prior_cleanup_preserves_every_hostile_or_unbound_artifact() {
        use std::os::unix::fs::symlink;

        let cases = [
            ("traversal", "../outside.sock"),
            ("out_of_root", "/tmp/not-neoth-connector-control.sock"),
            ("wrong_basename", "wrong.sock"),
        ];
        for (case, replacement) in cases {
            let home = crate::test_env::canonical_tempdir().unwrap();
            let audit_nonce = fresh_test_nonce();
            let endpoint = canonical_fixture(home.path(), &audit_nonce);
            bind_fixture_socket(&endpoint);
            let Endpoint::UnixSocket {
                path,
                home_sha256,
                runtime_nonce,
                ..
            } = &endpoint;
            let forged_path = if replacement.starts_with('/') {
                PathBuf::from(replacement)
            } else {
                path.parent().unwrap().join(replacement)
            };
            let raw = serde_json::json!({
                "schema_version": SIDECAR_SCHEMA_VERSION,
                "daemon_pid": std::process::id(),
                "endpoint_nonce": audit_nonce,
                "endpoint": {
                    "transport": "unix_socket",
                    "path": forged_path,
                    "endpoint_nonce": audit_nonce,
                    "home_sha256": home_sha256,
                    "runtime_nonce": runtime_nonce,
                }
            });
            std::fs::write(
                home.path().join(SIDECAR_FILE),
                serde_json::to_vec(&raw).unwrap(),
            )
            .unwrap();
            assert!(cleanup_prior_boot_artifacts(home.path()).is_err(), "{case}");
            assert!(path.exists(), "{case} must preserve the real socket");
            assert!(
                home.path().join(SIDECAR_FILE).exists(),
                "{case} must preserve the sidecar"
            );
        }

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        bind_fixture_socket(&endpoint);
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let foreign = path.parent().unwrap().join("foreign.sock");
        let foreign_listener = std::os::unix::net::UnixListener::bind(&foreign).unwrap();
        drop(foreign_listener);
        let mut foreign_endpoint = endpoint.clone();
        let Endpoint::UnixSocket { path, .. } = &mut foreign_endpoint;
        *path = foreign.clone();
        write_fixture_sidecar(home.path(), &foreign_endpoint, &audit_nonce);
        assert!(cleanup_prior_boot_artifacts(home.path()).is_err());
        assert!(foreign.exists());
        assert!(home.path().join(SIDECAR_FILE).exists());

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let target = home.path().join("symlink-target");
        std::fs::write(&target, b"preserve").unwrap();
        symlink(&target, path).unwrap();
        write_fixture_sidecar(home.path(), &endpoint, &audit_nonce);
        assert!(cleanup_prior_boot_artifacts(home.path()).is_err());
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(home.path().join(SIDECAR_FILE).exists());

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        std::fs::write(path, b"not-a-socket").unwrap();
        write_fixture_sidecar(home.path(), &endpoint, &audit_nonce);
        assert!(cleanup_prior_boot_artifacts(home.path()).is_err());
        assert!(path.exists());
        assert!(home.path().join(SIDECAR_FILE).exists());

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        std::fs::write(path, b"not-a-socket").unwrap();
        write_prebind(home.path(), &endpoint).unwrap();
        assert!(cleanup_prior_boot_artifacts(home.path()).is_err());
        assert!(path.exists());
        assert!(home.path().join(PREBIND_FILE).exists());

        for mutation in ["wrong_home", "wrong_nonce", "schema", "unknown_field"] {
            let home = crate::test_env::canonical_tempdir().unwrap();
            let audit_nonce = fresh_test_nonce();
            let endpoint = canonical_fixture(home.path(), &audit_nonce);
            bind_fixture_socket(&endpoint);
            let Endpoint::UnixSocket { path, .. } = &endpoint;
            let mut raw = serde_json::to_value(Sidecar {
                schema_version: SIDECAR_SCHEMA_VERSION,
                daemon_pid: std::process::id(),
                endpoint_nonce: &audit_nonce,
                endpoint: &endpoint,
            })
            .unwrap();
            match mutation {
                "wrong_home" => {
                    raw["endpoint"]["home_sha256"] = serde_json::json!("0".repeat(64));
                }
                "wrong_nonce" => {
                    raw["endpoint_nonce"] = serde_json::json!(different_test_nonce(&audit_nonce));
                }
                "schema" => raw["schema_version"] = serde_json::json!(SIDECAR_SCHEMA_VERSION + 1),
                "unknown_field" => raw["unexpected"] = serde_json::json!(true),
                _ => unreachable!(),
            }
            std::fs::write(
                home.path().join(SIDECAR_FILE),
                serde_json::to_vec(&raw).unwrap(),
            )
            .unwrap();
            assert!(
                cleanup_prior_boot_artifacts(home.path()).is_err(),
                "{mutation}"
            );
            assert!(path.exists(), "{mutation} must preserve the socket");
            assert!(
                home.path().join(SIDECAR_FILE).exists(),
                "{mutation} must preserve the sidecar"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn bind_before_sidecar_crash_cleanup_is_bounded_and_exact() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        for nonce in [fresh_test_nonce(), fresh_test_nonce()] {
            let endpoint = canonical_fixture(home.path(), &nonce);
            let Endpoint::UnixSocket { path, .. } = &endpoint;
            bind_fixture_socket(&endpoint);
            // Deliberately no sidecar: the durable pre-bind journal is the
            // exact locator left by a crash after bind but before publication.
            write_prebind(home.path(), &endpoint).unwrap();
            cleanup_prior_boot_artifacts(home.path()).unwrap();
            assert!(!path.exists());
            assert!(!path.parent().unwrap().exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn prebind_crash_before_directory_creation_is_recoverable() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = endpoint_for_home(home.path(), &audit_nonce).unwrap();
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let runtime_root = path.parent().unwrap().parent().unwrap().parent().unwrap();
        assert!(!runtime_root.exists());
        write_prebind(home.path(), &endpoint).unwrap();
        cleanup_prior_boot_artifacts(home.path()).unwrap();
        assert!(!home.path().join(PREBIND_FILE).exists());
        assert!(!runtime_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn prebind_cleanup_recovers_each_partial_directory_creation_stage() {
        for depth in 1..=3 {
            let home = crate::test_env::canonical_tempdir().unwrap();
            let audit_nonce = fresh_test_nonce();
            let endpoint = endpoint_for_home(home.path(), &audit_nonce).unwrap();
            let Endpoint::UnixSocket { path, .. } = &endpoint;
            let channel = path.parent().unwrap();
            let home_namespace = channel.parent().unwrap();
            let runtime_root = home_namespace.parent().unwrap();
            ensure_private_socket_directory(runtime_root, "test partial runtime root").unwrap();
            if depth >= 2 {
                ensure_private_socket_directory(home_namespace, "test partial home namespace")
                    .unwrap();
            }
            if depth >= 3 {
                ensure_private_socket_directory(channel, "test partial channel namespace").unwrap();
            }
            write_prebind(home.path(), &endpoint).unwrap();
            cleanup_prior_boot_artifacts(home.path()).unwrap();
            assert!(!runtime_root.exists(), "partial stage {depth}");
            assert!(
                !home.path().join(PREBIND_FILE).exists(),
                "partial stage {depth}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn prebind_crash_after_bind_before_socket_chmod_is_recoverable() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = canonical_fixture(home.path(), &audit_nonce);
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        // Model the dangerous bind-to-chmod crash window explicitly. Cleanup
        // may unlink this exact, journal-bound current-UID socket even though
        // publication would reject it until chmod 0600 succeeds.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        drop(listener);
        write_prebind(home.path(), &endpoint).unwrap();
        cleanup_prior_boot_artifacts(home.path()).unwrap();
        assert!(!path.exists());
        assert!(!home.path().join(PREBIND_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn hostile_global_tmp_junk_is_ignored_without_a_bound_prebind_journal() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let junk = Path::new("/tmp").join(format!(
            "{RUNTIME_ROOT_PREFIX}{}",
            random_runtime_nonce().unwrap()
        ));
        std::fs::write(&junk, b"foreign junk").unwrap();
        cleanup_prior_boot_artifacts(home.path()).unwrap();
        assert!(junk.exists());
        std::fs::remove_file(junk).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn runtime_root_is_unpredictable_and_precreated_victim_name_fails_closed() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let nonce = random_runtime_nonce().unwrap();
        let endpoint =
            endpoint_for_home_with_runtime_nonce(home.path(), &audit_nonce, &nonce).unwrap();
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let root = path.parent().unwrap().parent().unwrap().parent().unwrap();
        std::fs::write(root, b"attacker precreation").unwrap();
        assert!(ensure_endpoint_directories(&endpoint).is_err());
        assert!(root.is_file());
        std::fs::remove_file(root).unwrap();

        let second = endpoint_for_home(home.path(), &audit_nonce).unwrap();
        let Endpoint::UnixSocket {
            runtime_nonce: second_nonce,
            ..
        } = second;
        assert_ne!(nonce, second_nonce);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn endpoint_path_is_short_enough_to_bind_and_cleanup() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let audit_nonce = fresh_test_nonce();
        let endpoint = bind_endpoint(home.path(), &audit_nonce).unwrap();
        let Endpoint::UnixSocket { path, .. } = &endpoint;
        let runtime_parent = path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        assert_eq!(
            runtime_parent,
            std::fs::canonicalize("/tmp").unwrap().as_path(),
            "all endpoint comparison and cleanup syncs must use the resolved system temporary parent"
        );
        assert!(path.as_os_str().as_encoded_bytes().len() < MAX_UNIX_SOCKET_PATH_BYTES);
        // macOS accepts at most 104 pathname bytes in sockaddr_un; this
        // compact root deliberately contains no UID- or home-length input.
        assert!(path.as_os_str().as_encoded_bytes().len() < 104);
        let listener = bind_listener(&endpoint).unwrap();
        drop(listener);
        remove_endpoint_socket_and_empty_ancestors(home.path(), &endpoint).unwrap();
        assert!(!path.exists());
    }
}
