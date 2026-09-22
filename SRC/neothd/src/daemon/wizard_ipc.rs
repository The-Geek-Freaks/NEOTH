//! W204 private bootstrap IPC.  This module owns the live GUI-init token; the
//! wire protocol contains only non-secret wizard state and a prepared-config hash.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    task::{JoinHandle, JoinSet},
};

use crate::{
    cli::init::{
        GuiInitBeginAcknowledgement, begin_initialized_home_from_gui,
        complete_initialized_home_from_gui_with_prepared_hash,
    },
    wizard::ipc::{
        MAX_WIZARD_IPC_BODY_BYTES, WIZARD_IPC_PROTOCOL_VERSION, WizardBootId, WizardIpcMessage,
        WizardRejected, WizardRejectionCode, WizardRequest, WizardResponse, WizardSequence,
        WizardSessionId, WizardSnapshot, WizardStepId, WizardTerminalState,
    },
};

#[cfg(windows)]
const SERVICE: &str = "neoth-wizard-bootstrap-v1";
const TOKEN_FILE: &str = "wizard_ipc_token";
const SIDECAR_FILE: &str = "wizard_ipc.endpoint.v1.json";
const MAX_REQUEST_BYTES: usize = MAX_WIZARD_IPC_BODY_BYTES + 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_CONNECTIONS: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(5);
/// Leaves client I/O budget for connect/read/write after a server long poll.
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(3);

const COMMAND_CAPACITY: usize = 16;
#[derive(Clone)]
struct State {
    token: String,
    commands: tokio::sync::mpsc::Sender<WizardCommand>,
    updates: tokio::sync::watch::Sender<WizardSnapshot>,
}
struct WizardCommand {
    request: WizardRequest,
    reply: tokio::sync::oneshot::Sender<WizardResponse>,
}

/// Bootstrap lifetime lease. Stop admission before awaiting the server task.
pub struct WizardIpcGuard {
    shutdown: Arc<Shutdown>,
    home: PathBuf,
    /// Shared with the server task so guard drop cannot release it before owner drain.
    _pid_guard: Arc<crate::daemon::pidfile::PidGuard>,
    #[cfg(unix)]
    endpoint: Option<UnixEndpoint>,
}
impl WizardIpcGuard {
    pub fn stop(&self) {
        self.shutdown.stop();
        let _ = remove_private_child(&self.home, SIDECAR_FILE);
        let _ = remove_private_child(&self.home, TOKEN_FILE);
    }
}
impl Drop for WizardIpcGuard {
    fn drop(&mut self) {
        self.stop();
        #[cfg(unix)]
        if let Some(endpoint) = self.endpoint.take() {
            let _ = std::fs::remove_file(&endpoint.path);
            let _ = std::fs::remove_dir(endpoint.path.parent().unwrap_or(Path::new("/")));
        }
        let _ = remove_private_child(&self.home, SIDECAR_FILE);
        let _ = remove_private_child(&self.home, TOKEN_FILE);
    }
}
struct Shutdown {
    stopped: AtomicBool,
    notify: tokio::sync::Notify,
}
impl Shutdown {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    async fn cancelled(&self) {
        if self.stopped() {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.stopped() {
            return;
        }
        notified.await;
    }
}

struct WizardSessionService {
    home: PathBuf,
    acknowledgement: GuiInitBeginAcknowledgement,
    snapshot: WizardSnapshot,
}
impl WizardSessionService {
    fn new(home: &Path) -> Result<Self> {
        let acknowledgement = begin_initialized_home_from_gui(home)?;
        let mut boot = [0_u8; 32];
        getrandom::getrandom(&mut boot).context("wizard boot RNG unavailable")?;
        Ok(Self {
            home: acknowledgement.home.clone(),
            snapshot: WizardSnapshot {
                protocol_version: WIZARD_IPC_PROTOCOL_VERSION,
                session_id: WizardSessionId(acknowledgement.transaction_id.clone()),
                boot_id: WizardBootId(hex::encode(boot)),
                accepted_sequence: WizardSequence(0),
                current_step: WizardStepId::Welcome,
                terminal: WizardTerminalState::Active,
                last_message: None,
            },
            acknowledgement,
        })
    }
    fn rejection(&self, code: WizardRejectionCode) -> WizardResponse {
        WizardResponse::Rejected {
            rejection: WizardRejected {
                code,
                session_id: self.snapshot.session_id.clone(),
                boot_id: self.snapshot.boot_id.clone(),
                accepted_sequence: self.snapshot.accepted_sequence,
            },
        }
    }
    // Retain the existing typed rejection API consumed by all IPC request handlers.
    #[allow(clippy::result_large_err)]
    fn verify(
        &self,
        session: &WizardSessionId,
        boot: &WizardBootId,
        next: WizardSequence,
    ) -> std::result::Result<(), WizardResponse> {
        if boot != &self.snapshot.boot_id {
            return Err(self.rejection(WizardRejectionCode::StaleBoot));
        }
        if session != &self.snapshot.session_id {
            return Err(self.rejection(WizardRejectionCode::WrongSession));
        }
        if next.0 != self.snapshot.accepted_sequence.0.saturating_add(1) {
            return Err(self.rejection(WizardRejectionCode::OutOfOrder));
        }
        Ok(())
    }
    fn handle(&mut self, request: WizardRequest) -> WizardResponse {
        match request {
            WizardRequest::OpenOrResume => WizardResponse::SessionSnapshot {
                snapshot: self.snapshot.clone(),
            },
            WizardRequest::Snapshot => WizardResponse::SessionSnapshot {
                snapshot: self.snapshot.clone(),
            },
            WizardRequest::WaitForChange {
                session_id,
                boot_id,
                after_sequence,
            } => {
                if boot_id != self.snapshot.boot_id {
                    return self.rejection(WizardRejectionCode::StaleBoot);
                }
                if session_id != self.snapshot.session_id {
                    return self.rejection(WizardRejectionCode::WrongSession);
                }
                if after_sequence.0 > self.snapshot.accepted_sequence.0 {
                    return self.rejection(WizardRejectionCode::OutOfOrder);
                }
                WizardResponse::SessionSnapshot {
                    snapshot: self.snapshot.clone(),
                }
            }
            WizardRequest::Submit {
                session_id,
                boot_id,
                next_sequence,
                message,
            } => {
                if let Err(response) = self.verify(&session_id, &boot_id, next_sequence) {
                    return response;
                }
                if self.snapshot.terminal == WizardTerminalState::Cancelled {
                    return self.rejection(WizardRejectionCode::Cancelled);
                }
                if self.snapshot.terminal != WizardTerminalState::Active
                    || !matches!(message, WizardIpcMessage::ChannelOverride { .. })
                {
                    return self.rejection(WizardRejectionCode::NotReady);
                }
                self.snapshot.accepted_sequence = next_sequence;
                // The GUI has a real Channels toggle but no one-to-one W03
                // page. Project its admitted choice onto the nearest existing
                // non-welcome configuration stage; Slint still owns navigation.
                if matches!(message, WizardIpcMessage::ChannelOverride { .. }) {
                    self.snapshot.current_step = WizardStepId::Provider;
                }
                self.snapshot.last_message = Some(message);
                WizardResponse::Progress {
                    snapshot: self.snapshot.clone(),
                }
            }
            WizardRequest::Cancel {
                session_id,
                boot_id,
                next_sequence,
                from_step,
            } => {
                if let Err(response) = self.verify(&session_id, &boot_id, next_sequence) {
                    return response;
                }
                if self.snapshot.terminal != WizardTerminalState::Active {
                    return self.rejection(
                        if self.snapshot.terminal == WizardTerminalState::Cancelled {
                            WizardRejectionCode::Cancelled
                        } else {
                            WizardRejectionCode::NotReady
                        },
                    );
                }
                self.snapshot.accepted_sequence = next_sequence;
                self.snapshot.current_step = from_step;
                self.snapshot.last_message = None;
                self.snapshot.terminal = WizardTerminalState::Cancelled;
                WizardResponse::Progress {
                    snapshot: self.snapshot.clone(),
                }
            }
            WizardRequest::PrepareForCommit {
                session_id,
                boot_id,
                next_sequence,
                config_sha256,
            } => {
                if let Err(response) = self.verify(&session_id, &boot_id, next_sequence) {
                    return response;
                }
                if self.snapshot.terminal == WizardTerminalState::Cancelled {
                    return self.rejection(WizardRejectionCode::Cancelled);
                }
                if self.snapshot.terminal != WizardTerminalState::Active
                    || !lower_hex_64(&config_sha256)
                {
                    return self.rejection(WizardRejectionCode::NotReady);
                }
                let mut digest = [0_u8; 32];
                for (slot, offset) in digest.iter_mut().zip((0..64).step_by(2)) {
                    match u8::from_str_radix(&config_sha256[offset..offset + 2], 16) {
                        Ok(value) => *slot = value,
                        Err(_) => return self.rejection(WizardRejectionCode::NotReady),
                    }
                }
                // Glue owns the canonical lock and validates config + credentials + hash before marker commit.
                if complete_initialized_home_from_gui_with_prepared_hash(
                    &self.home,
                    &self.acknowledgement,
                    &digest,
                )
                .is_err()
                {
                    return self.rejection(WizardRejectionCode::NotReady);
                }
                self.snapshot.accepted_sequence = next_sequence;
                self.snapshot.current_step = WizardStepId::Finish;
                self.snapshot.last_message = Some(WizardIpcMessage::Finished);
                self.snapshot.terminal = WizardTerminalState::Completed;
                WizardResponse::Completed {
                    snapshot: self.snapshot.clone(),
                }
            }
        }
    }
}
pub(crate) fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The sole mutable session owner. It intentionally runs outside Tokio request
/// tasks: completion can perform canonical locked filesystem I/O, while IPC
/// tasks only enqueue a bounded command and await its one-shot reply.
fn spawn_owner(
    service: WizardSessionService,
    updates: tokio::sync::watch::Sender<WizardSnapshot>,
    shutdown: Arc<Shutdown>,
) -> Result<(
    tokio::sync::mpsc::Sender<WizardCommand>,
    std::thread::JoinHandle<()>,
)> {
    let (commands, mut receiver) = tokio::sync::mpsc::channel::<WizardCommand>(COMMAND_CAPACITY);
    let owner = std::thread::Builder::new().name("neoth-wizard-owner".into()).spawn(move || {
        let mut service = service;
        while let Some(command) = receiver.blocking_recv() {
            let response = service.handle(command.request);
            if let Some(snapshot) = response_snapshot(&response) {
                updates.send_if_modified(|published| {
                    if *published == *snapshot {
                        false
                    } else {
                        *published = snapshot.clone();
                        true
                    }
                });
            }
            let terminal = matches!(response, WizardResponse::Completed { .. }) || matches!(&response, WizardResponse::Progress { snapshot } if snapshot.terminal == WizardTerminalState::Cancelled);
            if !command.reply.is_closed() { let _ = command.reply.send(response); }
            // Terminal ownership is independent of an HTTP writer surviving
            // its deadline. Existing accepted writers drain before run_* exits.
            if terminal { shutdown.stop(); }
        }
    }).context("spawn wizard owner thread")?;
    Ok((commands, owner))
}
async fn dispatch(state: &State, request: WizardRequest) -> Result<WizardResponse> {
    let (reply, response) = tokio::sync::oneshot::channel();
    tokio::time::timeout(
        TIMEOUT,
        state.commands.send(WizardCommand { request, reply }),
    )
    .await
    .context("wizard owner admission deadline")?
    .map_err(|_| anyhow::anyhow!("wizard owner unavailable"))?;
    tokio::time::timeout(TIMEOUT, response)
        .await
        .context("wizard owner response deadline")?
        .map_err(|_| anyhow::anyhow!("wizard owner dropped command response"))
}

/// Bind one bootstrap endpoint for `home`. Constructing the service creates or
/// resumes the canonical pending init record; the acknowledgement token stays private.
#[cfg(unix)]
pub fn bind_and_serve(home: &Path) -> Result<(JoinHandle<Result<()>>, WizardIpcGuard)> {
    let pid_guard = Arc::new(crate::daemon::pidfile::acquire(&home.join("neothd.pid"))?);
    let service = WizardSessionService::new(home)?;
    let initial = service.snapshot.clone();
    let (updates, _) = tokio::sync::watch::channel(initial);
    let shutdown = Arc::new(Shutdown::new());
    let (commands, owner) = spawn_owner(service, updates.clone(), Arc::clone(&shutdown))?;
    let (token, endpoint) = match prepare_unix(home) {
        Ok(value) => value,
        Err(error) => {
            cleanup_failed_bind(home, None);
            return Err(error);
        }
    };
    let listener = match tokio::net::UnixListener::bind(&endpoint.path) {
        Ok(value) => value,
        Err(error) => {
            cleanup_failed_bind(home, Some(&endpoint));
            return Err(error.into());
        }
    };
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(error) =
        std::fs::set_permissions(&endpoint.path, std::fs::Permissions::from_mode(0o600))
    {
        drop(listener);
        cleanup_failed_bind(home, Some(&endpoint));
        return Err(error.into());
    }
    let task_lease = Arc::clone(&pid_guard);
    let task_shutdown = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        let result = run_unix(
            listener,
            State {
                token,
                commands,
                updates,
            },
            task_shutdown,
        )
        .await;
        let joined = tokio::task::spawn_blocking(move || owner.join())
            .await
            .context("join wizard owner task")?;
        joined.map_err(|_| anyhow::anyhow!("wizard owner thread panicked"))?;
        drop(task_lease);
        result
    });
    Ok((
        task,
        WizardIpcGuard {
            shutdown,
            home: home.to_path_buf(),
            _pid_guard: pid_guard,
            endpoint: Some(endpoint),
        },
    ))
}
#[cfg(windows)]
pub fn bind_and_serve(home: &Path) -> Result<(JoinHandle<Result<()>>, WizardIpcGuard)> {
    let pid_guard = Arc::new(crate::daemon::pidfile::acquire(&home.join("neothd.pid"))?);
    let service = WizardSessionService::new(home)?;
    let initial = service.snapshot.clone();
    let (updates, _) = tokio::sync::watch::channel(initial);
    let shutdown = Arc::new(Shutdown::new());
    let (commands, owner) = spawn_owner(service, updates.clone(), Arc::clone(&shutdown))?;
    let (token, endpoint) = match prepare_windows(home) {
        Ok(value) => value,
        Err(error) => {
            cleanup_failed_bind(home);
            return Err(error);
        }
    };
    let listener = match crate::windows_private_ipc::Listener::bind(
        endpoint,
        u32::try_from(MAX_REQUEST_BYTES).expect("request cap fits"),
    ) {
        Ok(value) => value,
        Err(error) => {
            cleanup_failed_bind(home);
            return Err(error);
        }
    };
    let task_lease = Arc::clone(&pid_guard);
    let task_shutdown = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        let result = run_windows(
            listener,
            State {
                token,
                commands,
                updates,
            },
            task_shutdown,
        )
        .await;
        let joined = tokio::task::spawn_blocking(move || owner.join())
            .await
            .context("join wizard owner task")?;
        joined.map_err(|_| anyhow::anyhow!("wizard owner thread panicked"))?;
        drop(task_lease);
        result
    });
    Ok((
        task,
        WizardIpcGuard {
            shutdown,
            home: home.to_path_buf(),
            _pid_guard: pid_guard,
        },
    ))
}
#[cfg(not(any(unix, windows)))]
pub fn bind_and_serve(_: &Path) -> Result<(JoinHandle<Result<()>>, WizardIpcGuard)> {
    bail!("wizard IPC is unavailable on this platform; no TCP fallback exists")
}

#[cfg(unix)]
async fn run_unix(
    listener: tokio::net::UnixListener,
    state: State,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut set = JoinSet::new();
    loop {
        let accepted = tokio::select! { _ = shutdown.cancelled() => break, joined = set.join_next(), if !set.is_empty() => { let _ = joined; continue }, value = listener.accept() => value? };
        let (stream, _) = accepted;
        if shutdown.stopped() || !same_effective_uid(&stream) {
            continue;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let shutdown = Arc::clone(&shutdown);
        set.spawn(async move {
            let _permit = permit;
            let _ = handle(stream, state, shutdown).await;
        });
    }
    while set.join_next().await.is_some() {}
    Ok(())
}
#[cfg(windows)]
async fn run_windows(
    mut listener: crate::windows_private_ipc::Listener,
    state: State,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut set = JoinSet::new();
    loop {
        let stream = tokio::select! { _ = shutdown.cancelled() => break, _ = set.join_next(), if !set.is_empty() => continue, value = listener.accept() => value? };
        if shutdown.stopped() {
            break;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let shutdown = Arc::clone(&shutdown);
        set.spawn(async move {
            let _permit = permit;
            let _ = handle(stream, state, shutdown).await;
        });
    }
    while set.join_next().await.is_some() {}
    Ok(())
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    state: State,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    let Some(request) = tokio::time::timeout(TIMEOUT, read_request(&mut stream))
        .await
        .ok()
        .flatten()
    else {
        return write_error(&mut stream, 400, "bad_request").await;
    };
    if !constant_time_eq(request.bearer.as_deref(), &state.token) {
        return write_error(&mut stream, 401, "unauthorized").await;
    }
    if shutdown.stopped() {
        return write_error(&mut stream, 503, "shutting_down").await;
    }
    if request.method != "POST" || request.path != "/wizard/v1/request" {
        return write_error(&mut stream, 404, "not_found").await;
    }
    let parsed: WizardRequest = match serde_json::from_slice::<WizardRequest>(&request.body) {
        Ok(value) if value.encoded_is_bounded() => value,
        _ => return write_error(&mut stream, 400, "invalid_wizard_request").await,
    };
    if let WizardRequest::WaitForChange {
        session_id,
        boot_id,
        after_sequence,
    } = parsed
    {
        return write_json(
            &mut stream,
            200,
            &wait_for_change(&state, session_id, boot_id, after_sequence).await?,
        )
        .await;
    }
    let response = dispatch(&state, parsed).await?;
    let terminal = matches!(response, WizardResponse::Completed { .. })
        || matches!(&response, WizardResponse::Progress { snapshot } if snapshot.terminal == WizardTerminalState::Cancelled);
    let result = write_json(&mut stream, 200, &response).await;
    if terminal {
        shutdown.stop();
    }
    result
}
fn response_snapshot(response: &WizardResponse) -> Option<&WizardSnapshot> {
    match response {
        WizardResponse::SessionSnapshot { snapshot }
        | WizardResponse::Progress { snapshot }
        | WizardResponse::CommitReady { snapshot }
        | WizardResponse::Completed { snapshot } => Some(snapshot),
        WizardResponse::Rejected { .. } => None,
    }
}
async fn wait_for_change(
    state: &State,
    session_id: WizardSessionId,
    boot_id: WizardBootId,
    after_sequence: WizardSequence,
) -> Result<WizardResponse> {
    let mut receiver = state.updates.subscribe();
    let expected_session_id = session_id.clone();
    let expected_boot_id = boot_id.clone();
    let current = dispatch(
        state,
        WizardRequest::WaitForChange {
            session_id,
            boot_id,
            after_sequence,
        },
    )
    .await?;
    let Some(snapshot) = response_snapshot(&current) else {
        return Ok(current);
    };
    if snapshot.accepted_sequence.0 > after_sequence.0
        || snapshot.terminal != WizardTerminalState::Active
    {
        return Ok(current);
    }
    let changed = matches!(
        tokio::time::timeout(LONG_POLL_TIMEOUT, receiver.changed()).await,
        Ok(Ok(()))
    );
    let snapshot = receiver.borrow().clone();
    if changed
        && snapshot.session_id == expected_session_id
        && snapshot.boot_id == expected_boot_id
        && (snapshot.accepted_sequence.0 > after_sequence.0
            || snapshot.terminal != WizardTerminalState::Active)
    {
        return Ok(WizardResponse::SessionSnapshot { snapshot });
    }
    Ok(current)
}

struct ParsedRequest {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
}
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<ParsedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    let header_end = loop {
        if bytes.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end - 4]).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    if first.next()? != "HTTP/1.1" || first.next().is_some() {
        return None;
    }
    let mut bearer = None;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("authorization") {
            if bearer.is_some() {
                return None;
            }
            bearer = value.trim().strip_prefix("Bearer ").map(str::to_owned);
        } else if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return None;
            }
            length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    let length = length?;
    if length > MAX_WIZARD_IPC_BODY_BYTES || header_end.checked_add(length)? > MAX_REQUEST_BYTES {
        return None;
    }
    let mut body = bytes[header_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > length {
            return None;
        }
    }
    Some(ParsedRequest {
        method,
        path,
        bearer,
        body,
    })
}
async fn write_json<S: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut S,
    status: u16,
    value: &T,
) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "wizard IPC response exceeds cap"
    );
    write_response(stream, status, &body).await
}
async fn write_error<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, code: &str) -> Result<()> {
    write_response(
        stream,
        status,
        format!(r#"{{"ok":false,"code":"{code}"}}"#).as_bytes(),
    )
    .await
}
async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(TIMEOUT, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await
    })
    .await
    .context("wizard IPC response deadline")??;
    Ok(())
}
fn constant_time_eq(candidate: Option<&str>, expected: &str) -> bool {
    candidate.is_some_and(|value| {
        value.len() == expected.len()
            && value
                .bytes()
                .zip(expected.bytes())
                .fold(0_u8, |d, (a, b)| d | (a ^ b))
                == 0
    })
}

#[cfg(unix)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixEndpoint {
    path: PathBuf,
    endpoint_nonce: String,
    home_sha256: String,
}
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixSidecar {
    schema_version: u8,
    endpoint: UnixEndpoint,
}
#[cfg(unix)]
fn prepare_unix(home: &Path) -> Result<(String, UnixEndpoint)> {
    let token = init_token(home)?;
    let canonical = std::fs::canonicalize(home)?;
    let nonce = random_nonce()?;
    let runtime = Path::new("/tmp").join(format!(".neoth-wizard-{}", &nonce[..16]));
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(&runtime)?;
    let endpoint = UnixEndpoint {
        path: runtime.join("wizard.sock"),
        endpoint_nonce: nonce,
        home_sha256: hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes())),
    };
    ensure!(
        endpoint.path.as_os_str().as_encoded_bytes().len() < 100,
        "wizard IPC socket path exceeds AF_UNIX cap"
    );
    write_private_json(
        home,
        SIDECAR_FILE,
        &UnixSidecar {
            schema_version: WIZARD_IPC_PROTOCOL_VERSION,
            endpoint: endpoint.clone(),
        },
    )?;
    Ok((token, endpoint))
}
#[cfg(windows)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsSidecar {
    schema_version: u8,
    endpoint_nonce: String,
    home_sha256: String,
}
#[cfg(windows)]
fn prepare_windows(
    home: &Path,
) -> Result<(String, crate::windows_private_ipc::PrivatePipeEndpoint)> {
    let token = init_token(home)?;
    let canonical = std::fs::canonicalize(home)?;
    let home_sha256 = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
    let endpoint_nonce = random_nonce()?;
    let endpoint = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
        SERVICE,
        &home_sha256,
        &endpoint_nonce,
    )?;
    write_private_json(
        home,
        SIDECAR_FILE,
        &WindowsSidecar {
            schema_version: WIZARD_IPC_PROTOCOL_VERSION,
            endpoint_nonce,
            home_sha256,
        },
    )?;
    Ok((token, endpoint))
}
fn init_token(home: &Path) -> Result<String> {
    let mut raw = [0_u8; 32];
    getrandom::getrandom(&mut raw)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    std::fs::create_dir_all(home)?;
    crate::wal::compaction::write_key_securely(&home.join(TOKEN_FILE), token.as_bytes())?;
    Ok(token)
}
fn random_nonce() -> Result<String> {
    let mut raw = [0_u8; 16];
    getrandom::getrandom(&mut raw)?;
    Ok(hex::encode(raw))
}
#[cfg(unix)]
fn cleanup_failed_bind(home: &Path, endpoint: Option<&UnixEndpoint>) {
    if let Some(endpoint) = endpoint {
        let _ = std::fs::remove_file(&endpoint.path);
        let _ = std::fs::remove_dir(endpoint.path.parent().unwrap_or(Path::new("/")));
    }
    let _ = remove_private_child(home, SIDECAR_FILE);
    let _ = remove_private_child(home, TOKEN_FILE);
}
#[cfg(windows)]
fn cleanup_failed_bind(home: &Path) {
    let _ = remove_private_child(home, SIDECAR_FILE);
    let _ = remove_private_child(home, TOKEN_FILE);
}
fn write_private_json<T: Serialize>(home: &Path, name: &str, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    let anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        anchor,
        home,
        true,
        "wizard IPC home",
    )?
    .context("wizard IPC home absent")?;
    let path = bound.display_path.join(name);
    crate::skills::store::atomic_write_private_child(&bound.dir, OsStr::new(name), &path, &body)?;
    Ok(())
}
fn remove_private_child(home: &Path, name: &str) -> Result<()> {
    let Some(bound) = crate::skills::store::open_bound_directory(home, false, "wizard IPC home")?
    else {
        return Ok(());
    };
    let path = bound.display_path.join(name);
    crate::skills::store::remove_child_file_if_present(&bound.dir, OsStr::new(name), &path)?;
    Ok(())
}

/// GUI-facing private client. Discovery binds sidecar home hash and the boot token.
#[derive(Clone)]
pub struct WizardIpcClient {
    #[cfg(unix)]
    endpoint: UnixEndpoint,
    #[cfg(windows)]
    endpoint: crate::windows_private_ipc::PrivatePipeEndpoint,
    token: String,
}
impl WizardIpcClient {
    #[cfg(unix)]
    pub fn discover(home: &Path) -> Result<Self> {
        let sidecar: UnixSidecar = read_private_json(home, SIDECAR_FILE)?;
        ensure!(
            sidecar.schema_version == WIZARD_IPC_PROTOCOL_VERSION,
            "wizard IPC sidecar schema mismatch"
        );
        let canonical = std::fs::canonicalize(home)?;
        ensure!(
            sidecar.endpoint.home_sha256
                == hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes())),
            "wizard IPC home mismatch"
        );
        Ok(Self {
            endpoint: sidecar.endpoint,
            token: read_token(home)?,
        })
    }
    #[cfg(windows)]
    pub fn discover(home: &Path) -> Result<Self> {
        let sidecar: WindowsSidecar = read_private_json(home, SIDECAR_FILE)?;
        ensure!(
            sidecar.schema_version == WIZARD_IPC_PROTOCOL_VERSION,
            "wizard IPC sidecar schema mismatch"
        );
        let canonical = std::fs::canonicalize(home)?;
        ensure!(
            sidecar.home_sha256
                == hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes())),
            "wizard IPC home mismatch"
        );
        Ok(Self {
            endpoint: crate::windows_private_ipc::PrivatePipeEndpoint::derive(
                SERVICE,
                &sidecar.home_sha256,
                &sidecar.endpoint_nonce,
            )?,
            token: read_token(home)?,
        })
    }
    pub async fn open_or_resume(&self) -> Result<WizardResponse> {
        self.request(WizardRequest::OpenOrResume).await
    }
    pub async fn snapshot(&self) -> Result<WizardResponse> {
        self.request(WizardRequest::Snapshot).await
    }
    pub async fn wait_for_change(
        &self,
        session_id: WizardSessionId,
        boot_id: WizardBootId,
        after_sequence: WizardSequence,
    ) -> Result<WizardResponse> {
        self.request(WizardRequest::WaitForChange {
            session_id,
            boot_id,
            after_sequence,
        })
        .await
    }
    pub async fn submit(
        &self,
        session_id: WizardSessionId,
        boot_id: WizardBootId,
        next_sequence: WizardSequence,
        message: WizardIpcMessage,
    ) -> Result<WizardResponse> {
        self.request(WizardRequest::Submit {
            session_id,
            boot_id,
            next_sequence,
            message,
        })
        .await
    }
    pub async fn prepare_for_commit(
        &self,
        session_id: WizardSessionId,
        boot_id: WizardBootId,
        next_sequence: WizardSequence,
        config_sha256: [u8; 32],
    ) -> Result<WizardResponse> {
        self.request(WizardRequest::PrepareForCommit {
            session_id,
            boot_id,
            next_sequence,
            config_sha256: hex::encode(config_sha256),
        })
        .await
    }
    pub async fn cancel(
        &self,
        session_id: WizardSessionId,
        boot_id: WizardBootId,
        next_sequence: WizardSequence,
        from_step: WizardStepId,
    ) -> Result<WizardResponse> {
        self.request(WizardRequest::Cancel {
            session_id,
            boot_id,
            next_sequence,
            from_step,
        })
        .await
    }
    async fn request(&self, request: WizardRequest) -> Result<WizardResponse> {
        let body = serde_json::to_vec(&request)?;
        ensure!(
            body.len() <= MAX_WIZARD_IPC_BODY_BYTES,
            "wizard IPC client body exceeds cap"
        );
        let header = format!(
            "POST /wizard/v1/request HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.token,
            body.len()
        );
        #[cfg(unix)]
        let response = {
            let mut stream = tokio::net::UnixStream::connect(&self.endpoint.path).await?;
            request_over_stream(&mut stream, header.as_bytes(), &body).await?
        };
        #[cfg(windows)]
        let response = {
            let mut stream = crate::windows_private_ipc::connect(&self.endpoint).await?;
            request_over_stream(&mut stream, header.as_bytes(), &body).await?
        };
        parse_response(&response)
    }
}
/// Test-only raw-auth seam for the platform-native listener tests. Production
/// callers cannot override the per-boot bearer or access private endpoints.
#[cfg(test)]
pub(crate) async fn request_for_test(
    home: &Path,
    request: WizardRequest,
    bearer_override: Option<&str>,
) -> Result<WizardResponse> {
    let mut client = WizardIpcClient::discover(home)?;
    if let Some(bearer) = bearer_override {
        client.token = bearer.to_owned();
    }
    client.request(request).await
}
async fn request_over_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    header: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    tokio::time::timeout(TIMEOUT, async {
        stream.write_all(header).await?;
        stream.write_all(body).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take((MAX_RESPONSE_BYTES + 1024) as u64)
            .read_to_end(&mut response)
            .await?;
        ensure!(
            response.len() <= MAX_RESPONSE_BYTES + 1024,
            "wizard IPC response exceeds cap"
        );
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .context("wizard IPC client deadline")?
}
fn parse_response(bytes: &[u8]) -> Result<WizardResponse> {
    let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        bail!("wizard IPC response malformed")
    };
    ensure!(
        std::str::from_utf8(&bytes[..i])?.starts_with("HTTP/1.1 200 "),
        "wizard daemon rejected request"
    );
    serde_json::from_slice(&bytes[i + 4..]).context("decode wizard IPC response")
}
fn read_token(home: &Path) -> Result<String> {
    let bytes = read_private_child(home, TOKEN_FILE)?;
    let token = String::from_utf8(crate::wal::compaction::maybe_unwrap_dpapi(
        &bytes,
        &home.join(TOKEN_FILE),
    )?)?
    .trim()
    .to_owned();
    ensure!(!token.is_empty(), "wizard IPC token empty");
    Ok(token)
}
fn read_private_json<T: for<'de> Deserialize<'de>>(home: &Path, name: &str) -> Result<T> {
    Ok(serde_json::from_slice(&read_private_child(home, name)?)?)
}
fn read_private_child(home: &Path, name: &str) -> Result<Vec<u8>> {
    let bound = crate::skills::store::open_bound_directory(home, false, "wizard IPC home")?
        .context("wizard IPC home absent")?;
    let path = bound.display_path.join(name);
    crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(name),
        &path,
        MAX_RESPONSE_BYTES,
    )
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn same_effective_uid(stream: &tokio::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd as _;
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        ) == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credential.assume_init().uid == libc::geteuid()
    }
}
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn same_effective_uid(_: &tokio::net::UnixStream) -> bool {
    true
}

#[cfg(test)]
#[path = "wizard_ipc_tests.rs"]
mod tests;
