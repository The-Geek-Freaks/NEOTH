//! Same-user, daemon-lifetime IPC for a paired Obsidian Archive Bridge.
//!
//! The wire is one bounded newline-delimited JSON request and one response.
//! It has no TCP listener and accepts no note text or filesystem paths.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
    },
};

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::obsidian_archive_bridge_owner::{ArchiveBridgeOwner, SyncRequest};

const MAX_LINE_BYTES: usize = 8 * 1024;
#[cfg(windows)]
const SERVICE: &str = "neoth-obsidian-bridge-v1";

#[derive(Clone)]
struct Shutdown {
    stopped: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
    async fn cancelled(&self) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// Dropping or explicitly stopping the guard withdraws this daemon boot's
/// bridge listener. Pairing material remains inert on disk until the next
/// daemon boot rebinds the same private endpoint.
pub(crate) struct ArchiveBridgeIpcGuard {
    shutdown: Shutdown,
    #[cfg(unix)]
    socket: PathBuf,
    #[cfg(unix)]
    socket_device: u64,
    #[cfg(unix)]
    socket_inode: u64,
}
impl Drop for ArchiveBridgeIpcGuard {
    fn drop(&mut self) {
        self.shutdown.stop();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if let Ok(metadata) = std::fs::symlink_metadata(&self.socket)
                && metadata.dev() == self.socket_device
                && metadata.ino() == self.socket_inode
            {
                let _ = std::fs::remove_file(&self.socket);
            }
        }
    }
}

/// Owns one published listener.  Dropping the guard withdraws the endpoint;
/// `drain` then waits for the accept loop to finish its admitted work.
pub(crate) struct ArchiveBridgeIpcBinding {
    guard: ArchiveBridgeIpcGuard,
    completion: Receiver<Result<()>>,
}

impl ArchiveBridgeIpcBinding {
    pub(crate) fn withdraw_and_drain(self) -> Result<()> {
        let Self { guard, completion } = self;
        drop(guard);
        completion
            .recv()
            .map_err(|_| anyhow::anyhow!("Obsidian bridge listener completion channel closed"))?
    }
}

pub(crate) fn bind_and_serve(
    home: &Path,
    owner: Arc<ArchiveBridgeOwner>,
) -> Result<ArchiveBridgeIpcBinding> {
    let Some(endpoint) = owner.endpoint_name() else {
        bail!("cannot bind Obsidian bridge IPC without a pairing");
    };
    let shutdown = Shutdown::new();
    #[cfg(any(unix, windows))]
    let runtime = tokio::runtime::Handle::try_current()
        .context("Obsidian bridge IPC must bind from the daemon Tokio runtime")?;
    #[cfg(unix)]
    {
        let socket = PathBuf::from(&endpoint);
        recover_owned_stale_socket(home, &socket)?;
        ensure!(
            !socket.exists(),
            "refuse to replace an existing Obsidian bridge socket"
        );
        ensure!(
            socket.as_os_str().as_encoded_bytes().len() < 100,
            "Obsidian bridge socket path exceeds AF_UNIX cap"
        );
        let listener = tokio::net::UnixListener::bind(&socket)
            .with_context(|| format!("bind Obsidian bridge socket {}", socket.display()))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        use std::os::unix::fs::MetadataExt as _;
        let metadata = match std::fs::symlink_metadata(&socket) {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = std::fs::remove_file(&socket);
                return Err(error).context("read freshly bound Obsidian bridge socket identity");
            }
        };
        let (completion_tx, completion) = std::sync::mpsc::sync_channel(1);
        let task_shutdown = shutdown.clone();
        runtime.spawn(async move {
            let _ = completion_tx.send(run_unix(listener, owner, task_shutdown).await);
        });
        Ok(ArchiveBridgeIpcBinding {
            guard: ArchiveBridgeIpcGuard {
                shutdown,
                socket,
                socket_device: metadata.dev(),
                socket_inode: metadata.ino(),
            },
            completion,
        })
    }
    #[cfg(windows)]
    {
        let nonce = owner
            .endpoint_nonce()
            .context("bridge pairing has no endpoint nonce")?;
        let canonical = std::fs::canonicalize(home)
            .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
        use sha2::{Digest as _, Sha256};
        let home_hash = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
        let pipe =
            crate::windows_private_ipc::PrivatePipeEndpoint::derive(SERVICE, &home_hash, &nonce)?;
        ensure!(
            pipe.name() == endpoint,
            "paired bridge endpoint binding mismatch"
        );
        let listener = crate::windows_private_ipc::Listener::bind(pipe, MAX_LINE_BYTES as u32)?;
        let (completion_tx, completion) = std::sync::mpsc::sync_channel(1);
        let task_shutdown = shutdown.clone();
        runtime.spawn(async move {
            let _ = completion_tx.send(run_windows(listener, owner, task_shutdown).await);
        });
        return Ok(ArchiveBridgeIpcBinding {
            guard: ArchiveBridgeIpcGuard { shutdown },
            completion,
        });
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (home, owner, shutdown);
        bail!("Obsidian bridge IPC unavailable on this platform")
    }
}

/// Recover only a crash-left socket while this daemon owns the PID lock.  A
/// reachable socket, a non-socket, another UID, or a leaf replaced during the
/// probe remains fail-closed and is never unlinked.
#[cfg(unix)]
fn recover_owned_stale_socket(home: &Path, socket: &Path) -> Result<()> {
    recover_owned_stale_socket_with_probe(home, socket, |socket| {
        crate::daemon::audit_rpc::probe_unix_socket_refused(
            socket,
            std::time::Duration::from_millis(500),
        )
        .context("bounded probe pre-existing Obsidian bridge socket")
    })
}

#[cfg(unix)]
fn recover_owned_stale_socket_with_probe(
    home: &Path,
    socket: &Path,
    probe: impl FnOnce(&Path) -> Result<bool>,
) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let before = match std::fs::symlink_metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect pre-existing Obsidian bridge socket"),
    };
    ensure!(
        before.file_type().is_socket(),
        "refuse to recover non-socket Obsidian bridge leaf"
    );
    // SAFETY: geteuid reads the calling process's effective UID without pointers or preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    ensure!(
        before.uid() == effective_uid,
        "refuse to recover Obsidian bridge socket owned by another UID"
    );
    ensure!(
        crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))?
            == Some(std::process::id()),
        "refuse stale Obsidian bridge recovery without this daemon's held PID lock"
    );
    ensure!(
        !probe(socket)?,
        "refuse to replace a reachable Obsidian bridge listener"
    );
    let after = std::fs::symlink_metadata(socket)
        .context("recheck pre-existing Obsidian bridge socket before recovery")?;
    ensure!(
        after.file_type().is_socket()
            && after.uid() == before.uid()
            && after.dev() == before.dev()
            && after.ino() == before.ino(),
        "refuse recovery because the Obsidian bridge socket changed during probe"
    );
    std::fs::remove_file(socket).context("remove verified stale Obsidian bridge socket")
}

#[cfg(unix)]
async fn run_unix(
    listener: tokio::net::UnixListener,
    owner: Arc<ArchiveBridgeOwner>,
    shutdown: Shutdown,
) -> Result<()> {
    loop {
        let accepted = tokio::select! { _ = shutdown.cancelled() => break, value = listener.accept() => value? };
        let (stream, _) = accepted;
        let _ = handle(stream, Arc::clone(&owner)).await;
    }
    Ok(())
}

#[cfg(windows)]
async fn run_windows(
    mut listener: crate::windows_private_ipc::Listener,
    owner: Arc<ArchiveBridgeOwner>,
    shutdown: Shutdown,
) -> Result<()> {
    loop {
        let stream = tokio::select! { _ = shutdown.cancelled() => break, value = listener.accept() => value? };
        let _ = handle(stream, Arc::clone(&owner)).await;
    }
    Ok(())
}

async fn handle<S>(stream: S, owner: Arc<ArchiveBridgeOwner>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let frame = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_frame(&mut reader),
    )
    .await
    {
        Ok(Ok(frame)) => frame,
        _ => return Ok(()),
    };
    let response = match serde_json::from_slice::<Request>(&frame) {
        Ok(Request::Status {
            protocol,
            pairing_secret,
            pairing_generation,
        }) if protocol == 1 => {
            let response = tokio::task::spawn_blocking(move || {
                owner.authorize_status(protocol, &pairing_secret, pairing_generation)
            })
            .await
            .unwrap_or(super::obsidian_archive_bridge_owner::SyncResponse {
                status: "error",
                generation: None,
            });
            ErrorResponse {
                status: response.status,
                generation: response.generation,
            }
        }
        Ok(Request::Sync(request)) => {
            let owner = Arc::clone(&owner);
            let response = tokio::task::spawn_blocking(move || owner.sync(request))
                .await
                .unwrap_or(super::obsidian_archive_bridge_owner::SyncResponse {
                    status: "error",
                    generation: None,
                });
            ErrorResponse {
                status: response.status,
                generation: response.generation,
            }
        }
        _ => ErrorResponse {
            status: "invalid_request",
            generation: None,
        },
    };
    write(&mut writer, response).await
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status {
        protocol: u8,
        #[serde(rename = "pairingSecret")]
        pairing_secret: String,
        #[serde(rename = "generation")]
        pairing_generation: u64,
    },
    Sync(SyncRequest),
}
#[derive(Serialize)]
struct ErrorResponse {
    status: &'static str,
    generation: Option<u64>,
}
async fn write<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    value: ErrorResponse,
) -> Result<()> {
    let mut encoded = serde_json::to_vec(&value)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let count = reader.read(&mut byte).await?;
        ensure!(count != 0, "bridge IPC peer closed before a request frame");
        if byte[0] == b'\n' {
            return Ok(frame);
        }
        ensure!(
            frame.len() < MAX_LINE_BYTES,
            "bridge IPC request exceeds frame limit"
        );
        frame.push(byte[0]);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn stale_owned_socket_is_recovered_only_after_current_pid_lock_is_held() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let socket = home.path().join("stale-obsidian-bridge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        drop(listener);
        assert!(
            recover_owned_stale_socket(home.path(), &socket).is_err(),
            "a stale-looking socket is preserved until this daemon owns the PID lock"
        );
        let _pid = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        recover_owned_stale_socket(home.path(), &socket).unwrap();
        assert!(
            !socket.exists(),
            "verified unreachable owned socket is removed"
        );
    }

    #[test]
    fn reachable_socket_is_never_recovered() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let _pid = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        let socket = home.path().join("live-obsidian-bridge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(recover_owned_stale_socket(home.path(), &socket).is_err());
        assert!(socket.exists(), "reachable listener leaf is preserved");
        drop(listener);
    }

    #[test]
    fn socket_replaced_during_stale_probe_is_never_removed() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let _pid = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        let socket = home.path().join("replaced-obsidian-bridge.sock");
        let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        drop(stale);
        let replacement = std::sync::Mutex::new(None);
        assert!(
            recover_owned_stale_socket_with_probe(home.path(), &socket, |_| {
                std::fs::remove_file(&socket).unwrap();
                *replacement.lock().unwrap() =
                    Some(std::os::unix::net::UnixListener::bind(&socket).unwrap());
                Ok(false)
            })
            .is_err()
        );
        assert!(
            socket.exists(),
            "replacement leaf remains after identity recheck"
        );
    }
}
