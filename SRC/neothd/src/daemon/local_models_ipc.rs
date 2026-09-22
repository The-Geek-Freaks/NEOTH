//! Current-user local IPC for the daemon-owned Local Models controller.
//!
//! This is deliberately separate from Connector Control Plane RPC.  It exposes
//! only status, operation admission, and exact-operation cancellation over an
//! OS-private endpoint.  The bearer is per-daemon-boot protocol proof; it is
//! not a network credential and no TCP fallback exists.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    task::{JoinHandle, JoinSet},
};

use super::local_models::{
    LocalModelAction, LocalModelActionAck, LocalModelController, LocalModelsSnapshot,
};

#[cfg(windows)]
const SERVICE: &str = "neoth-local-models-v1";
const TOKEN_FILE: &str = "local_models_ipc_token";
const SIDECAR_FILE: &str = "local_models_ipc.endpoint.v1.json";
const SCHEMA_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_ENVELOPE_BYTES: usize = MAX_RESPONSE_BYTES + 1024;
const MAX_CONNECTIONS: usize = 16;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct State {
    token: String,
    service: Arc<dyn LocalModelsService>,
}

#[async_trait]
trait LocalModelsService: Send + Sync {
    async fn status(&self) -> LocalModelsSnapshot;
    async fn start(&self, action: LocalModelAction) -> LocalModelActionAck;
    async fn cancel(&self, operation_id: &str) -> LocalModelActionAck;
}

#[async_trait]
impl LocalModelsService for LocalModelController {
    async fn status(&self) -> LocalModelsSnapshot {
        self.status().await
    }

    async fn start(&self, action: LocalModelAction) -> LocalModelActionAck {
        self.start(action).await
    }

    async fn cancel(&self, operation_id: &str) -> LocalModelActionAck {
        self.cancel(operation_id).await
    }
}

/// Explicit lifetime handle.  Dropping it closes admission immediately; await
/// the returned server task to prove every accepted connection has drained.
pub(crate) struct LocalModelsIpcGuard {
    shutdown: Arc<Shutdown>,
    home: PathBuf,
    #[cfg(unix)]
    endpoint: Option<UnixEndpoint>,
}

impl LocalModelsIpcGuard {
    pub(crate) fn stop(&self) {
        self.shutdown.stop();
    }
}

impl Drop for LocalModelsIpcGuard {
    fn drop(&mut self) {
        self.shutdown.stop();
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
    admission: Mutex<()>,
    notify: tokio::sync::Notify,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            admission: Mutex::new(()),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn stop(&self) {
        let _guard = self.admission.lock();
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.stopped() {
            return;
        }
        let notified = self.notify.notified();
        if self.stopped() {
            return;
        }
        notified.await;
    }
}

/// Bind the per-daemon local-model endpoint.  The caller owns both returned
/// values for the daemon lifetime and must await the task after stopping guard.
#[cfg(unix)]
pub(crate) fn bind_and_serve(
    home: &Path,
    controller: Arc<LocalModelController>,
) -> Result<(JoinHandle<Result<()>>, LocalModelsIpcGuard)> {
    bind_with_service(home, controller)
}

#[cfg(windows)]
pub(crate) fn bind_and_serve(
    home: &Path,
    controller: Arc<LocalModelController>,
) -> Result<(JoinHandle<Result<()>>, LocalModelsIpcGuard)> {
    bind_with_service(home, controller)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn bind_and_serve(
    _: &Path,
    _: Arc<LocalModelController>,
) -> Result<(JoinHandle<Result<()>>, LocalModelsIpcGuard)> {
    bail!("local-model IPC is unavailable on this platform; no TCP fallback exists")
}

#[cfg(unix)]
fn bind_with_service(
    home: &Path,
    service: Arc<dyn LocalModelsService>,
) -> Result<(JoinHandle<Result<()>>, LocalModelsIpcGuard)> {
    let (token, endpoint) = prepare_unix(home)?;
    let listener = tokio::net::UnixListener::bind(&endpoint.path)
        .with_context(|| format!("bind local-model IPC socket {}", endpoint.path.display()))?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&endpoint.path, std::fs::Permissions::from_mode(0o600))?;
    let shutdown = Arc::new(Shutdown::new());
    let task = tokio::spawn(run_unix_listener(
        listener,
        State { token, service },
        Arc::clone(&shutdown),
    ));
    Ok((
        task,
        LocalModelsIpcGuard {
            shutdown,
            home: home.to_path_buf(),
            endpoint: Some(endpoint),
        },
    ))
}

#[cfg(windows)]
fn bind_with_service(
    home: &Path,
    service: Arc<dyn LocalModelsService>,
) -> Result<(JoinHandle<Result<()>>, LocalModelsIpcGuard)> {
    let (token, endpoint) = prepare_windows(home)?;
    let listener = crate::windows_private_ipc::Listener::bind(
        endpoint,
        u32::try_from(MAX_REQUEST_BYTES).expect("request bound fits u32"),
    )?;
    let shutdown = Arc::new(Shutdown::new());
    let task = tokio::spawn(run_windows_listener(
        listener,
        State { token, service },
        Arc::clone(&shutdown),
    ));
    Ok((
        task,
        LocalModelsIpcGuard {
            shutdown,
            home: home.to_path_buf(),
        },
    ))
}

#[cfg(unix)]
async fn run_unix_listener(
    listener: tokio::net::UnixListener,
    state: State,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        let accepted = if connections.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                value = listener.accept() => value.map_err(anyhow::Error::from)?,
            }
        } else {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                joined = connections.join_next() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(%error, "local-model IPC connection task panicked");
                    }
                    continue;
                }
                value = listener.accept() => value.map_err(anyhow::Error::from)?,
            }
        };
        let (stream, _) = accepted;
        if shutdown.stopped() || !same_effective_uid(&stream) {
            drop(stream);
            continue;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        let shutdown = Arc::clone(&shutdown);
        connections.spawn(async move {
            let _permit = permit;
            let _ = handle_connection(stream, state, shutdown).await;
        });
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(windows)]
async fn run_windows_listener(
    mut listener: crate::windows_private_ipc::Listener,
    state: State,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        let stream = if connections.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                value = listener.accept() => value?,
            }
        } else {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = connections.join_next() => continue,
                value = listener.accept() => value?,
            }
        };
        if shutdown.stopped() {
            drop(stream);
            break;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        let shutdown = Arc::clone(&shutdown);
        connections.spawn(async move {
            let _permit = permit;
            let _ = handle_connection(stream, state, shutdown).await;
        });
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection<S>(mut stream: S, state: State, shutdown: Arc<Shutdown>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match tokio::time::timeout(CONNECTION_TIMEOUT, read_request(&mut stream)).await {
        Ok(Some(request)) => request,
        _ => {
            write_error(&mut stream, 400, "bad_request").await?;
            return Ok(());
        }
    };
    if !constant_time_eq(request.bearer.as_deref(), &state.token) {
        write_error(&mut stream, 401, "unauthorized").await?;
        return Ok(());
    }
    if shutdown.stopped() {
        write_error(&mut stream, 503, "shutting_down").await?;
        return Ok(());
    }

    let path = request.path.split('?').next().unwrap_or_default();
    match (request.method.as_str(), path) {
        ("GET", "/local-models/v1/status") if request.body.is_empty() => {
            let snapshot = state.service.status().await;
            write_json(&mut stream, 200, &snapshot).await
        }
        ("POST", "/local-models/v1/operations") => {
            let request: StartRequest = match serde_json::from_slice(&request.body) {
                Ok(value) => value,
                Err(_) => {
                    write_error(&mut stream, 400, "invalid_operation_request").await?;
                    return Ok(());
                }
            };
            // Core admission is fast and returns an ACK while the controller
            // retains the mutation. It must never be detached from the core.
            let ack = state.service.start(request.action).await;
            write_json(&mut stream, 200, &ack).await
        }
        ("POST", route) => {
            let Some(operation_id) = route
                .strip_prefix("/local-models/v1/operations/")
                .and_then(|tail| tail.strip_suffix("/cancel"))
            else {
                write_error(&mut stream, 404, "not_found").await?;
                return Ok(());
            };
            if operation_id.is_empty()
                || operation_id.len() > 256
                || !operation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !request.body.is_empty()
            {
                write_error(&mut stream, 400, "invalid_cancel_request").await?;
                return Ok(());
            }
            let ack = state.service.cancel(operation_id).await;
            write_json(&mut stream, 200, &ack).await
        }
        _ => write_error(&mut stream, 404, "not_found").await,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    action: LocalModelAction,
}

struct ParsedRequest {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
}

async fn read_request<S>(stream: &mut S) -> Option<ParsedRequest>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if bytes.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let count = stream.read(&mut chunk).await.ok()?;
        if count == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end - 4]).ok()?;
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
            bearer = value.trim().strip_prefix("Bearer ").map(str::to_owned);
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return None;
            }
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    let length = content_length?;
    if length > MAX_BODY_BYTES || header_end.checked_add(length)? > MAX_REQUEST_BYTES {
        return None;
    }
    let mut body = bytes[header_end..].to_vec();
    while body.len() < length {
        let count = stream.read(&mut chunk).await.ok()?;
        if count == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..count]);
        if body.len() > length {
            return None;
        }
    }
    (body.len() == length).then_some(ParsedRequest {
        method,
        path,
        bearer,
        body,
    })
}

async fn write_json<S, T>(stream: &mut S, status: u16, value: &T) -> Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value).context("encode local-model IPC response")?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "local-model IPC response exceeds cap"
    );
    write_response(stream, status, &body).await
}

async fn write_error<S>(stream: &mut S, status: u16, code: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_response(
        stream,
        status,
        format!(r#"{{"ok":false,"code":"{code}"}}"#).as_bytes(),
    )
    .await
}

async fn write_response<S>(stream: &mut S, status: u16, body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_line(status),
        body.len()
    );
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await
    })
    .await
    .context("local-model IPC response deadline exceeded")??;
    Ok(())
}

fn status_line(status: u16) -> &'static str {
    match status {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        401 => "HTTP/1.1 401 Unauthorized",
        404 => "HTTP/1.1 404 Not Found",
        503 => "HTTP/1.1 503 Service Unavailable",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

fn constant_time_eq(candidate: Option<&str>, expected: &str) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

#[cfg(unix)]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    let canonical = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let home_sha256 = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
    let nonce = random_nonce()?;
    let runtime = Path::new("/tmp").join(format!(".neoth-local-models-{}", &nonce[..16]));
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(&runtime)?;
    let path = runtime.join("local-models.sock");
    ensure!(
        path.as_os_str().as_encoded_bytes().len() < 100,
        "local-model IPC socket path exceeds AF_UNIX cap"
    );
    let endpoint = UnixEndpoint {
        path,
        endpoint_nonce: nonce,
        home_sha256,
    };
    write_private_json(
        home,
        SIDECAR_FILE,
        &UnixSidecar {
            schema_version: SCHEMA_VERSION,
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
    let canonical = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
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
            schema_version: SCHEMA_VERSION,
            endpoint_nonce,
            home_sha256,
        },
    )?;
    Ok((token, endpoint))
}

fn init_token(home: &Path) -> Result<String> {
    let mut raw = [0_u8; 32];
    getrandom::getrandom(&mut raw).context("OS RNG unavailable for local-model IPC token")?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    std::fs::create_dir_all(home)?;
    crate::wal::compaction::write_key_securely(&home.join(TOKEN_FILE), token.as_bytes())
        .context("write local-model IPC token")?;
    Ok(token)
}

fn random_nonce() -> Result<String> {
    let mut raw = [0_u8; 16];
    getrandom::getrandom(&mut raw).context("OS RNG unavailable for local-model IPC endpoint")?;
    Ok(hex::encode(raw))
}

fn write_private_json<T: Serialize>(home: &Path, name: &str, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "local-model IPC sidecar exceeds cap"
    );
    let trusted_anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        home,
        true,
        "local-model IPC home directory",
    )?
    .context("local-model IPC home was not created")?;
    let path = bound.display_path.join(name);
    crate::skills::store::atomic_write_private_child(&bound.dir, OsStr::new(name), &path, &body)?;
    Ok(())
}

fn remove_private_child(home: &Path, name: &str) -> Result<()> {
    let Some(bound) =
        crate::skills::store::open_bound_directory(home, false, "local-model IPC home directory")?
    else {
        return Ok(());
    };
    let path = bound.display_path.join(name);
    crate::skills::store::remove_child_file_if_present(&bound.dir, OsStr::new(name), &path)?;
    Ok(())
}

/// Client discovery reads only this service's sidecar and per-boot token.
pub(crate) struct LocalModelsIpcClient {
    #[cfg(unix)]
    endpoint: UnixEndpoint,
    #[cfg(windows)]
    endpoint: crate::windows_private_ipc::PrivatePipeEndpoint,
    token: String,
}

impl LocalModelsIpcClient {
    #[cfg(unix)]
    pub(crate) fn discover(home: &Path) -> Result<Self> {
        let sidecar: UnixSidecar = read_private_json(home, SIDECAR_FILE)?;
        ensure!(
            sidecar.schema_version == SCHEMA_VERSION,
            "local-model IPC sidecar schema mismatch"
        );
        let canonical = std::fs::canonicalize(home)?;
        let expected_home = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
        ensure!(
            sidecar.endpoint.home_sha256 == expected_home,
            "local-model IPC sidecar home mismatch"
        );
        Ok(Self {
            endpoint: sidecar.endpoint,
            token: read_token(home)?,
        })
    }

    #[cfg(windows)]
    pub(crate) fn discover(home: &Path) -> Result<Self> {
        let sidecar: WindowsSidecar = read_private_json(home, SIDECAR_FILE)?;
        ensure!(
            sidecar.schema_version == SCHEMA_VERSION,
            "local-model IPC sidecar schema mismatch"
        );
        let canonical = std::fs::canonicalize(home)?;
        let expected_home = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
        ensure!(
            sidecar.home_sha256 == expected_home,
            "local-model IPC sidecar home mismatch"
        );
        let endpoint = crate::windows_private_ipc::PrivatePipeEndpoint::derive(
            SERVICE,
            &sidecar.home_sha256,
            &sidecar.endpoint_nonce,
        )?;
        Ok(Self {
            endpoint,
            token: read_token(home)?,
        })
    }

    pub(crate) async fn status(&self) -> Result<LocalModelsSnapshot> {
        self.request("GET", "/local-models/v1/status", &[]).await
    }

    pub(crate) async fn start(&self, action: LocalModelAction) -> Result<LocalModelActionAck> {
        self.request(
            "POST",
            "/local-models/v1/operations",
            &serde_json::to_vec(&StartRequestRef { action: &action })?,
        )
        .await
    }

    pub(crate) async fn cancel(&self, operation_id: &str) -> Result<LocalModelActionAck> {
        ensure!(
            !operation_id.is_empty() && operation_id.len() <= 256,
            "invalid local-model operation id"
        );
        self.request(
            "POST",
            &format!("/local-models/v1/operations/{operation_id}/cancel"),
            &[],
        )
        .await
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        route: &str,
        body: &[u8],
    ) -> Result<T> {
        ensure!(
            body.len() <= MAX_BODY_BYTES,
            "local-model IPC client body exceeds cap"
        );
        let request = format!(
            "{method} {route} HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.token,
            body.len()
        );
        #[cfg(unix)]
        let response = {
            let mut stream = tokio::net::UnixStream::connect(&self.endpoint.path).await?;
            request_over_stream(&mut stream, request.as_bytes(), body).await?
        };
        #[cfg(windows)]
        let response = {
            let mut stream = crate::windows_private_ipc::connect(&self.endpoint).await?;
            request_over_stream(&mut stream, request.as_bytes(), body).await?
        };
        parse_success_response(&response)
    }
}

#[derive(Serialize)]
struct StartRequestRef<'a> {
    action: &'a LocalModelAction,
}

async fn request_over_stream<S>(stream: &mut S, header: &[u8], body: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        stream.write_all(header).await?;
        stream.write_all(body).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take((MAX_RESPONSE_ENVELOPE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await?;
        ensure!(
            response.len() <= MAX_RESPONSE_ENVELOPE_BYTES,
            "local-model IPC response exceeds cap"
        );
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .context("local-model IPC client deadline exceeded")?
}

fn parse_success_response<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let Some((head, body)) = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (&bytes[..index], &bytes[index + 4..]))
    else {
        bail!("local-model IPC response is malformed");
    };
    let head = std::str::from_utf8(head)?;
    ensure!(
        head.starts_with("HTTP/1.1 200 "),
        "local-model IPC daemon rejected request"
    );
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "local-model IPC response body exceeds cap"
    );
    serde_json::from_slice(body).context("decode local-model IPC response")
}

fn read_token(home: &Path) -> Result<String> {
    let bytes = read_private_child(home, TOKEN_FILE, MAX_RESPONSE_BYTES)?;
    let token = String::from_utf8(crate::wal::compaction::maybe_unwrap_dpapi(
        &bytes,
        &home.join(TOKEN_FILE),
    )?)?
    .trim()
    .to_owned();
    ensure!(!token.is_empty(), "local-model IPC token is empty");
    Ok(token)
}

fn read_private_json<T: for<'de> Deserialize<'de>>(home: &Path, name: &str) -> Result<T> {
    let bytes = read_private_child(home, name, MAX_RESPONSE_BYTES)?;
    serde_json::from_slice(&bytes).context("decode local-model IPC sidecar")
}

fn read_private_child(home: &Path, name: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let bound =
        crate::skills::store::open_bound_directory(home, false, "local-model IPC home directory")?
            .context("local-model IPC home is absent")?;
    let path = bound.display_path.join(name);
    crate::skills::store::read_regular_file_bounded(&bound.dir, OsStr::new(name), &path, max_bytes)
        .with_context(|| format!("read private local-model IPC artifact {}", path.display()))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn same_effective_uid(stream: &tokio::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd as _;
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: stream owns a live Unix socket for this call. The writable
    // buffer is exactly ucred-sized and length points to initialized storage.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return false;
    }
    // SAFETY: successful SO_PEERCRED with the checked exact length initialized
    // every field of ucred. geteuid has no pointer or lifetime preconditions.
    unsafe { credential.assume_init().uid == libc::geteuid() }
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
    // SAFETY: stream owns a live Unix socket; uid/gid are valid exclusive
    // out-pointers for the call. Read them only on success. geteuid is pointer-free.
    unsafe {
        libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == libc::geteuid()
    }
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
    false
}

#[cfg(test)]
mod tests {
    use super::super::local_models::{
        LocalEndpointStatus, LocalHostResources, LocalModelActionKind,
    };
    use super::*;
    use tokio::io::duplex;

    fn request(method: &str, path: &str, bearer: &str, body: &[u8]) -> Vec<u8> {
        [format!("{method} {path} HTTP/1.1\r\nAuthorization: Bearer {bearer}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(), body.to_vec()].concat()
    }

    #[tokio::test]
    async fn fixture_request_parses_exact_status_route() {
        let (mut client, mut server) = duplex(MAX_REQUEST_BYTES);
        let fixture = request("GET", "/local-models/v1/status", "fixture", b"");
        tokio::spawn(async move {
            client.write_all(&fixture).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let parsed = read_request(&mut server).await.unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/local-models/v1/status");
        assert_eq!(parsed.bearer.as_deref(), Some("fixture"));
    }

    #[tokio::test]
    async fn malformed_request_is_rejected() {
        let (mut client, mut server) = duplex(128);
        tokio::spawn(async move {
            client.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            client.shutdown().await.unwrap();
        });
        assert!(read_request(&mut server).await.is_none());
    }

    #[tokio::test]
    async fn request_size_bound_is_rejected() {
        let (mut client, mut server) = duplex(MAX_REQUEST_BYTES + 64);
        let payload = vec![b'x'; MAX_REQUEST_BYTES];
        tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        assert!(read_request(&mut server).await.is_none());
    }

    #[test]
    fn unauthorized_bearer_fails_closed() {
        assert!(!constant_time_eq(Some("wrong"), "correct"));
        assert!(!constant_time_eq(None, "correct"));
        assert!(constant_time_eq(Some("correct"), "correct"));
    }

    #[test]
    fn cancel_route_requires_exact_bounded_operation_id() {
        let route = "/local-models/v1/operations/op-0123/cancel";
        let id = route
            .strip_prefix("/local-models/v1/operations/")
            .unwrap()
            .strip_suffix("/cancel")
            .unwrap();
        assert_eq!(id, "op-0123");
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }

    #[derive(Default)]
    struct FixtureService {
        entered_start: tokio::sync::Notify,
        release_start: tokio::sync::Notify,
        started: Mutex<Option<String>>,
        cancelled: Mutex<Option<String>>,
    }

    fn fixture_snapshot() -> LocalModelsSnapshot {
        LocalModelsSnapshot {
            schema_version: 1,
            observed_at_unix_ms: 1,
            endpoint: LocalEndpointStatus::Unavailable {
                detail: "fixture".to_owned(),
            },
            host_resources: LocalHostResources::default(),
            models: Vec::new(),
            active_operation: None,
            last_terminal_operation: None,
        }
    }

    #[async_trait]
    impl LocalModelsService for FixtureService {
        async fn status(&self) -> LocalModelsSnapshot {
            fixture_snapshot()
        }

        async fn start(&self, action: LocalModelAction) -> LocalModelActionAck {
            let action_kind = match &action {
                LocalModelAction::Pull { model } => {
                    *self.started.lock().unwrap() = Some(format!("pull:{model}"));
                    LocalModelActionKind::Pull
                }
                LocalModelAction::Update { model } => {
                    *self.started.lock().unwrap() = Some(format!("update:{model}"));
                    LocalModelActionKind::Update
                }
                LocalModelAction::Prune { model } => {
                    *self.started.lock().unwrap() = Some(format!("prune:{model}"));
                    LocalModelActionKind::Prune
                }
                LocalModelAction::Retry {
                    terminal_operation_id,
                } => {
                    *self.started.lock().unwrap() = Some(format!("retry:{terminal_operation_id}"));
                    LocalModelActionKind::Retry
                }
            };
            self.entered_start.notify_one();
            self.release_start.notified().await;
            LocalModelActionAck {
                schema_version: 1,
                ok: true,
                action: action_kind,
                operation_id: Some("op-long".to_owned()),
                error: None,
                snapshot: fixture_snapshot(),
            }
        }

        async fn cancel(&self, operation_id: &str) -> LocalModelActionAck {
            *self.cancelled.lock().unwrap() = Some(operation_id.to_owned());
            LocalModelActionAck {
                schema_version: 1,
                ok: true,
                action: LocalModelActionKind::Pull,
                operation_id: Some(operation_id.to_owned()),
                error: None,
                snapshot: fixture_snapshot(),
            }
        }
    }

    async fn fixture_exchange(state: State, request_bytes: Vec<u8>) -> Vec<u8> {
        let (mut client, server) = duplex(MAX_REQUEST_BYTES + MAX_RESPONSE_ENVELOPE_BYTES);
        let shutdown = Arc::new(Shutdown::new());
        let handler = tokio::spawn(handle_connection(server, state, shutdown));
        client.write_all(&request_bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        handler.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn status_and_exact_cancel_route_while_start_is_pending() {
        let service = Arc::new(FixtureService::default());
        let state = State {
            token: "fixture".to_owned(),
            service: service.clone(),
        };
        let (mut long_client, long_server) =
            duplex(MAX_REQUEST_BYTES + MAX_RESPONSE_ENVELOPE_BYTES);
        let long_handler = tokio::spawn(handle_connection(
            long_server,
            state.clone(),
            Arc::new(Shutdown::new()),
        ));
        long_client
            .write_all(&request(
                "POST",
                "/local-models/v1/operations",
                "fixture",
                br#"{"action":{"kind":"pull","model":"tiny"}}"#,
            ))
            .await
            .unwrap();
        long_client.shutdown().await.unwrap();
        service.entered_start.notified().await;

        let status = fixture_exchange(
            state.clone(),
            request("GET", "/local-models/v1/status", "fixture", b""),
        )
        .await;
        assert!(status.starts_with(b"HTTP/1.1 200"));
        let cancel = fixture_exchange(
            state,
            request(
                "POST",
                "/local-models/v1/operations/op-long/cancel",
                "fixture",
                b"",
            ),
        )
        .await;
        assert!(cancel.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            service.cancelled.lock().unwrap().as_deref(),
            Some("op-long")
        );

        service.release_start.notify_one();
        let mut long_response = Vec::new();
        long_client.read_to_end(&mut long_response).await.unwrap();
        long_handler.await.unwrap().unwrap();
        assert!(long_response.starts_with(b"HTTP/1.1 200"));
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn native_bind_discovery_client_roundtrip_drains_after_stop() {
        let home = tempfile::tempdir().unwrap();
        let service = Arc::new(FixtureService::default());
        let (listener_task, guard) = bind_with_service(home.path(), service.clone()).unwrap();
        let client = Arc::new(LocalModelsIpcClient::discover(home.path()).unwrap());

        let snapshot = client.status().await.unwrap();
        assert_eq!(snapshot.schema_version, 1);

        let start_client = Arc::clone(&client);
        let start = tokio::spawn(async move {
            start_client
                .start(LocalModelAction::Pull {
                    model: "tiny".to_owned(),
                })
                .await
        });
        service.entered_start.notified().await;
        assert_eq!(
            service.started.lock().unwrap().as_deref(),
            Some("pull:tiny")
        );

        // The long start owns its connection, while independent native-client
        // status and exact cancel routes remain available over fresh streams.
        let status_client = Arc::clone(&client);
        let cancel_client = Arc::clone(&client);
        let (status, cancel) =
            tokio::join!(status_client.status(), cancel_client.cancel("op-long"),);
        assert_eq!(status.unwrap().schema_version, 1);
        assert!(cancel.unwrap().ok);
        assert_eq!(
            service.cancelled.lock().unwrap().as_deref(),
            Some("op-long")
        );

        service.release_start.notify_one();
        assert_eq!(
            start.await.unwrap().unwrap().operation_id.as_deref(),
            Some("op-long")
        );

        guard.stop();
        drop(guard);
        listener_task.await.unwrap().unwrap();
        assert!(LocalModelsIpcClient::discover(home.path()).is_err());
    }
    #[tokio::test]
    async fn shutdown_signal_is_observable_without_detaching_waiters() {
        let shutdown = Arc::new(Shutdown::new());
        let waiter = {
            let shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move {
                shutdown.cancelled().await;
                shutdown.stopped()
            })
        };
        tokio::task::yield_now().await;
        shutdown.stop();
        assert!(waiter.await.unwrap());
    }
    #[test]
    fn response_fixture_requires_success_status_and_json_body() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Fixture {
            value: u8,
        }
        let value: Fixture =
            parse_success_response(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"value\":1}")
                .unwrap();
        assert_eq!(value, Fixture { value: 1 });
        assert!(parse_success_response::<Fixture>(b"HTTP/1.1 401 Unauthorized\r\n\r\n{}").is_err());
    }
}
