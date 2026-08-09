use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use tokio::net::{UnixListener, UnixStream};

use super::{AuditEndpointV2, AuditStream};

const RUNTIME_DIRECTORY_PREFIX: &str = "c-";
const HOME_NAMESPACE_PREFIX: &str = "h-";
const RUNTIME_ROOT_PREFIX: &str = ".neoth-audit-rpc-v3-";
const HOME_NAMESPACE_HEX_LEN: usize = 24;
const CHANNEL_DIRECTORY_HEX_LEN: usize = 24;
const SOCKET_FILE_NAME: &str = "audit.sock";
const MAX_RUNTIME_ENTRIES_FOR_STALE_CLEANUP: usize = 4096;
const MAX_STALE_DIRECTORY_ENTRIES: usize = 4;
const STALE_CLEANUP_BUDGET: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

pub(super) struct Listener {
    listener: Option<UnixListener>,
    home_namespace: PathBuf,
    runtime_directory: PathBuf,
    socket_path: PathBuf,
    home_namespace_identity: FileIdentity,
    runtime_identity: FileIdentity,
    socket_identity: FileIdentity,
}

pub(super) fn runtime_directory_name(home_sha256: &str, endpoint_nonce: &str) -> String {
    let digest = super::channel_hash(home_sha256, endpoint_nonce);
    format!(
        "{RUNTIME_DIRECTORY_PREFIX}{}",
        &digest[..CHANNEL_DIRECTORY_HEX_LEN]
    )
}

fn home_namespace_name(home_sha256: &str) -> String {
    let digest = super::home_namespace_hash(home_sha256);
    format!(
        "{HOME_NAMESPACE_PREFIX}{}",
        &digest[..HOME_NAMESPACE_HEX_LEN]
    )
}

/// Return the short, private per-user root used for pathname Unix sockets.
///
/// `/tmp` is only a sticky system-owned ancestor. It never contains an
/// audit-RPC socket directly: every endpoint lives below an exclusively
/// created, same-UID, mode-0700 root. Keeping that root fixed and short avoids
/// macOS's `sockaddr_un::sun_path` limit for deeply nested canonical homes.
pub(super) fn private_runtime_root() -> Result<PathBuf> {
    let temporary_parent = Path::new("/tmp");
    let canonical_temporary_parent = std::fs::canonicalize(temporary_parent)
        .context("canonicalize system temporary directory for audit-RPC")?;
    let metadata = std::fs::symlink_metadata(&canonical_temporary_parent).with_context(|| {
        format!(
            "inspect system temporary directory {} for audit-RPC",
            canonical_temporary_parent.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "audit-RPC system temporary directory is not a real directory"
    );
    ensure!(
        metadata.mode() & 0o022 == 0 || metadata.mode() & libc::S_ISVTX != 0,
        "audit-RPC system temporary directory is writable without sticky-bit protection"
    );
    // Keep the serialized/bound socket spelling at `/tmp/...`, even on macOS
    // where `/tmp` resolves to `/private/tmp`: the fixed short spelling is
    // what makes the address length independent of the canonical home path.
    Ok(temporary_parent.join(format!("{RUNTIME_ROOT_PREFIX}{}", effective_uid())))
}

/// Derive the only Unix socket path accepted for a canonical-home hash and
/// endpoint nonce. The hash and nonce are both fed into the directory digest;
/// the full canonical-home hash remains serialized in `AuditEndpointV2` and is
/// re-derived by `AuditEndpointV2::validate` before a sidecar is accepted.
pub(super) fn socket_path(home_sha256: &str, endpoint_nonce: &str) -> Result<PathBuf> {
    let path = private_runtime_root()?
        .join(home_namespace_name(home_sha256))
        .join(runtime_directory_name(home_sha256, endpoint_nonce))
        .join(SOCKET_FILE_NAME);
    validate_socket_path_length(&path)?;
    Ok(path)
}

pub(super) fn validate_endpoint_shape(
    path: &Path,
    endpoint_nonce: &str,
    home_sha256: &str,
) -> Result<()> {
    super::validate_endpoint_nonce(endpoint_nonce)?;
    super::validate_home_sha256(home_sha256)?;
    ensure!(
        path.is_absolute(),
        "audit-RPC Unix socket path is not absolute"
    );
    ensure!(
        path.file_name().and_then(|name| name.to_str()) == Some(SOCKET_FILE_NAME),
        "audit-RPC Unix socket has an invalid file name"
    );
    ensure!(
        path == socket_path(home_sha256, endpoint_nonce)?.as_path(),
        "audit-RPC Unix socket path is not bound to canonical-home hash and endpoint nonce"
    );
    Ok(())
}

impl Listener {
    pub(super) fn bind(endpoint: &AuditEndpointV2) -> Result<Self> {
        let AuditEndpointV2::UnixSocket {
            path,
            endpoint_nonce,
            home_sha256,
        } = endpoint;
        validate_endpoint_shape(path, endpoint_nonce, home_sha256)?;

        let runtime_directory = path
            .parent()
            .context("audit-RPC Unix socket has no runtime directory")?
            .to_path_buf();
        let home_namespace = runtime_directory
            .parent()
            .context("audit-RPC runtime directory has no home namespace")?;
        let home_namespace_metadata = ensure_private_home_namespace(home_namespace, home_sha256)?;
        cleanup_stale_runtime_directories(home_namespace, &runtime_directory, home_sha256)?;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(&runtime_directory) {
            remove_if_identity_matches(
                home_namespace,
                Some(FileIdentity::from_metadata(&home_namespace_metadata)),
                false,
            );
            return Err(error).with_context(|| {
                format!(
                    "create exclusive audit-RPC runtime directory {}",
                    runtime_directory.display()
                )
            });
        }

        let result = (|| {
            let runtime_metadata =
                verify_runtime_directory(&runtime_directory).with_context(|| {
                    format!(
                        "verify audit-RPC runtime directory {}",
                        runtime_directory.display()
                    )
                })?;
            let listener = UnixListener::bind(path)
                .with_context(|| format!("bind audit-RPC Unix socket {}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("set audit-RPC socket mode 0600 on {}", path.display()))?;
            let socket_metadata = verify_socket(path)
                .with_context(|| format!("verify audit-RPC socket {}", path.display()))?;
            Ok(Self {
                listener: Some(listener),
                home_namespace: home_namespace.to_path_buf(),
                runtime_directory: runtime_directory.clone(),
                socket_path: path.clone(),
                home_namespace_identity: FileIdentity::from_metadata(&home_namespace_metadata),
                runtime_identity: FileIdentity::from_metadata(&runtime_metadata),
                socket_identity: FileIdentity::from_metadata(&socket_metadata),
            })
        })();

        if result.is_err() {
            remove_if_identity_matches(path, None, true);
            remove_if_identity_matches(&runtime_directory, None, false);
            remove_if_identity_matches(
                home_namespace,
                Some(FileIdentity::from_metadata(&home_namespace_metadata)),
                false,
            );
        }
        result
    }

    pub(super) async fn accept(&mut self) -> Result<AuditStream> {
        let listener = self
            .listener
            .as_ref()
            .context("audit-RPC Unix listener is closed")?;
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .context("accept audit-RPC Unix connection")?;
            if attest_same_effective_uid(&stream).is_ok() {
                return Ok(Box::new(stream));
            }
            // Fail this connection closed, but keep serving legitimate peers.
            drop(stream);
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        drop(self.listener.take());
        remove_if_identity_matches(&self.socket_path, Some(self.socket_identity), true);
        remove_if_identity_matches(&self.runtime_directory, Some(self.runtime_identity), false);
        remove_if_identity_matches(
            &self.home_namespace,
            Some(self.home_namespace_identity),
            false,
        );
    }
}

pub(super) async fn connect(endpoint: &AuditEndpointV2) -> Result<AuditStream> {
    let AuditEndpointV2::UnixSocket {
        path,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    validate_endpoint_shape(path, endpoint_nonce, home_sha256)?;
    let before = verify_endpoint_path(path, home_sha256)?;
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect audit-RPC Unix socket {}", path.display()))?;
    attest_same_effective_uid(&stream)?;
    let after = verify_endpoint_path(path, home_sha256)?;
    ensure!(
        before == after,
        "audit-RPC Unix endpoint changed while connecting"
    );
    Ok(Box::new(stream))
}

pub(super) fn exchange_blocking(
    endpoint: &AuditEndpointV2,
    request: &[u8],
    max_response: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let AuditEndpointV2::UnixSocket {
        path,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    validate_endpoint_shape(path, endpoint_nonce, home_sha256)?;
    let before = verify_endpoint_path(path, home_sha256)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("audit-RPC timeout overflow")?;
    let mut stream = connect_std_with_deadline(path, deadline)
        .with_context(|| format!("connect audit-RPC Unix socket {}", path.display()))?;
    attest_same_effective_uid(&stream)?;
    let after = verify_endpoint_path(path, home_sha256)?;
    ensure!(
        before == after,
        "audit-RPC Unix endpoint changed while connecting"
    );

    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .context("set audit-RPC Unix write timeout")?;
    stream
        .write_all(request)
        .context("write audit-RPC Unix request")?;

    let mut response = Vec::with_capacity(max_response.min(8192));
    let mut chunk = [0_u8; 8192];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .context("set audit-RPC Unix read timeout")?;
        let allowed = max_response
            .checked_add(1)
            .context("audit-RPC response bound overflow")?
            .saturating_sub(response.len());
        if allowed == 0 {
            anyhow::bail!("audit-RPC response exceeds {max_response} bytes");
        }
        let read_limit = chunk.len().min(allowed);
        let read = stream
            .read(&mut chunk[..read_limit])
            .context("read audit-RPC Unix response")?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        ensure!(
            response.len() <= max_response,
            "audit-RPC response exceeds {max_response} bytes"
        );
    }
    Ok(response)
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "audit-RPC blocking exchange timed out"
    );
    Ok(remaining)
}

/// Establish a Unix-domain stream without ever entering a potentially
/// unbounded blocking `connect(2)`. The nonblocking socket remains owned by
/// `RawFdGuard` until all connect/poll/SO_ERROR checks have succeeded.
fn connect_std_with_deadline(path: &Path, deadline: Instant) -> Result<StdUnixStream> {
    let path_bytes = path.as_os_str().as_bytes();
    validate_socket_path_length(path)?;
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    // SAFETY: zeroed is a valid initial representation for sockaddr_un.
    let address = unsafe { address.assume_init_mut() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *destination = *source as libc::c_char;
    }
    let address_length = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(path_bytes.len() + 1)
        .context("audit-RPC Unix socket address length overflow")?;
    let address_length = libc::socklen_t::try_from(address_length)
        .context("audit-RPC Unix socket address length does not fit socklen_t")?;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len = u8::try_from(address_length)
            .context("audit-RPC Unix socket address length does not fit sun_len")?;
    }

    // SAFETY: AF_UNIX/SOCK_STREAM/protocol zero is a valid socket request.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("create audit-RPC Unix socket");
    }
    let guard = RawFdGuard(raw);
    set_fd_flag(guard.0, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)?;
    set_fd_flag(guard.0, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)?;

    // SAFETY: address is fully initialized for address_length bytes and the
    // guarded descriptor is a live AF_UNIX stream socket.
    let connected = unsafe {
        libc::connect(
            guard.0,
            (address as *const libc::sockaddr_un).cast(),
            address_length,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        let raw_error = error.raw_os_error();
        if raw_error != Some(libc::EINPROGRESS)
            && raw_error != Some(libc::EAGAIN)
            && raw_error != Some(libc::EWOULDBLOCK)
        {
            return Err(error).context("start nonblocking audit-RPC Unix connect");
        }
        wait_for_connect(guard.0, deadline)?;
    }

    clear_fd_flag(guard.0, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)?;
    // SAFETY: `guard` uniquely owns this live connected descriptor; after
    // from_raw_fd, forgetting the guard transfers that exact ownership.
    let stream = unsafe { StdUnixStream::from_raw_fd(guard.0) };
    std::mem::forget(guard);
    Ok(stream)
}

fn set_fd_flag(
    fd: RawFd,
    get_command: libc::c_int,
    set_command: libc::c_int,
    flag: libc::c_int,
) -> Result<()> {
    // SAFETY: fcntl is called with commands whose return/value contract is
    // an integer flag word for this live descriptor.
    let current = unsafe { libc::fcntl(fd, get_command) };
    if current < 0 {
        return Err(std::io::Error::last_os_error()).context("read Unix descriptor flags");
    }
    // SAFETY: the setter accepts the combined integer flag word.
    if unsafe { libc::fcntl(fd, set_command, current | flag) } < 0 {
        return Err(std::io::Error::last_os_error()).context("set Unix descriptor flags");
    }
    Ok(())
}

fn clear_fd_flag(
    fd: RawFd,
    get_command: libc::c_int,
    set_command: libc::c_int,
    flag: libc::c_int,
) -> Result<()> {
    // SAFETY: same fcntl flag-word contract as `set_fd_flag`.
    let current = unsafe { libc::fcntl(fd, get_command) };
    if current < 0 {
        return Err(std::io::Error::last_os_error()).context("read Unix descriptor flags");
    }
    // SAFETY: the setter accepts the combined integer flag word.
    if unsafe { libc::fcntl(fd, set_command, current & !flag) } < 0 {
        return Err(std::io::Error::last_os_error()).context("clear Unix descriptor flags");
    }
    Ok(())
}

fn wait_for_connect(fd: RawFd, deadline: Instant) -> Result<()> {
    loop {
        let timeout = remaining(deadline)?;
        let timeout_ms = i32::try_from(timeout.as_millis().clamp(1, i32::MAX as u128))
            .context("audit-RPC Unix connect timeout does not fit poll")?;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd for this live
        // descriptor and the timeout is bounded by the caller deadline.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error).context("poll audit-RPC Unix connect");
        }
        ensure!(ready != 0, "audit-RPC blocking exchange timed out");

        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: both output pointers are valid for an integer SO_ERROR
        // result and the descriptor is still owned by RawFdGuard.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("read audit-RPC Unix connect result");
        }
        ensure!(
            length as usize == std::mem::size_of::<libc::c_int>(),
            "SO_ERROR returned an invalid result length"
        );
        if socket_error != 0 {
            return Err(std::io::Error::from_raw_os_error(socket_error))
                .context("complete audit-RPC Unix connect");
        }
        return Ok(());
    }
}

struct RawFdGuard(RawFd);

impl Drop for RawFdGuard {
    fn drop(&mut self) {
        // SAFETY: this guard owns the descriptor until ownership is
        // explicitly transferred into StdUnixStream.
        unsafe {
            libc::close(self.0);
        }
    }
}

fn validate_socket_path_length(path: &Path) -> Result<()> {
    let path_bytes = path.as_os_str().as_bytes();
    ensure!(
        !path_bytes.contains(&0),
        "audit-RPC Unix socket path contains an interior NUL"
    );
    let address = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    // SAFETY: a zeroed sockaddr_un is a valid representation and reading the
    // fixed array length does not inspect an uninitialized field.
    let sun_path_length = unsafe { address.assume_init_ref() }.sun_path.len();
    ensure!(
        path_bytes.len() < sun_path_length,
        "audit-RPC Unix socket path is too long for sockaddr_un"
    );
    Ok(())
}

pub(super) fn ensure_private_home(home: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(home)
        .with_context(|| format!("inspect NEOTH home {}", home.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "NEOTH home is not a real directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "NEOTH home is not owned by the effective user"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "NEOTH home is group/world writable; private audit-RPC endpoint is unsafe"
    );
    crate::util::darwin_acl::verify_directory_has_no_extended_acl(home).with_context(|| {
        format!(
            "verify NEOTH home {} has no macOS extended ACL",
            home.display()
        )
    })?;
    Ok(())
}

fn ensure_private_runtime_root(root: &Path) -> Result<()> {
    let expected = private_runtime_root()?;
    ensure!(
        root == expected,
        "audit-RPC runtime root is not the expected private same-user root"
    );
    let mut builder = std::fs::DirBuilder::new();
    // `mkdir(2)` receives 0700 even if the caller's umask is permissive, so
    // there is never a window where another user can enter a newly created
    // root below the shared sticky ancestor.
    builder.mode(0o700);
    match builder.create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("create private audit-RPC runtime root {}", root.display())
            });
        }
    }
    verify_private_runtime_root(root).map(|_| ())
}

pub(super) fn ensure_private_home_namespace(
    namespace: &Path,
    home_sha256: &str,
) -> Result<std::fs::Metadata> {
    let root = private_runtime_root()?;
    ensure_private_runtime_root(&root)?;
    let expected = root.join(home_namespace_name(home_sha256));
    ensure!(
        namespace == expected,
        "audit-RPC home namespace is not bound to the canonical-home hash"
    );
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(namespace) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "create private audit-RPC home namespace {}",
                    namespace.display()
                )
            });
        }
    }
    verify_private_home_namespace(namespace, home_sha256)
}

fn verify_private_runtime_root(path: &Path) -> Result<std::fs::Metadata> {
    let expected = private_runtime_root()?;
    ensure!(
        path == expected,
        "audit-RPC runtime root is not the expected private same-user root"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "audit-RPC runtime root is not a real directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "audit-RPC runtime root is not owned by the effective user"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o700,
        "audit-RPC runtime root mode is not 0700"
    );
    crate::util::darwin_acl::verify_directory_has_no_extended_acl(path).with_context(|| {
        format!(
            "verify audit-RPC runtime root {} has no macOS extended ACL",
            path.display()
        )
    })?;
    Ok(metadata)
}

fn verify_private_home_namespace(namespace: &Path, home_sha256: &str) -> Result<std::fs::Metadata> {
    let root = private_runtime_root()?;
    verify_private_runtime_root(&root)?;
    ensure!(
        namespace == root.join(home_namespace_name(home_sha256)),
        "audit-RPC home namespace is not bound to the canonical-home hash"
    );
    let metadata = std::fs::symlink_metadata(namespace)?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "audit-RPC home namespace is not a real directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "audit-RPC home namespace is not owned by the effective user"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o700,
        "audit-RPC home namespace mode is not 0700"
    );
    crate::util::darwin_acl::verify_directory_has_no_extended_acl(namespace).with_context(
        || {
            format!(
                "verify audit-RPC home namespace {} has no macOS extended ACL",
                namespace.display()
            )
        },
    )?;
    Ok(metadata)
}

/// Remove only nonce directories that are provably ours and provably
/// inactive.  The directory for the current nonce is always excluded so a
/// pre-created current endpoint still makes bind fail closed.
fn cleanup_stale_runtime_directories(
    home_namespace: &Path,
    current: &Path,
    home_sha256: &str,
) -> Result<()> {
    verify_private_home_namespace(home_namespace, home_sha256)?;
    let deadline = Instant::now()
        .checked_add(STALE_CLEANUP_BUDGET)
        .context("audit-RPC stale cleanup deadline overflow")?;
    let entries = std::fs::read_dir(home_namespace).with_context(|| {
        format!(
            "scan private audit-RPC home namespace {} for stale audit sockets",
            home_namespace.display()
        )
    })?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_RUNTIME_ENTRIES_FOR_STALE_CLEANUP || Instant::now() >= deadline {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_runtime_directory_name(name) {
            continue;
        }
        let path = entry.path();
        if path == current {
            continue;
        }
        let Ok(directory_metadata) = verify_runtime_directory(&path) else {
            continue;
        };
        let directory_identity = FileIdentity::from_metadata(&directory_metadata);
        let Ok(children) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut child_count = 0;
        let mut socket_metadata = None;
        let mut unexpected_child = false;
        for child in children {
            child_count += 1;
            if child_count > MAX_STALE_DIRECTORY_ENTRIES {
                unexpected_child = true;
                break;
            }
            let Ok(child) = child else {
                unexpected_child = true;
                break;
            };
            if child.file_name() != SOCKET_FILE_NAME {
                unexpected_child = true;
                break;
            }
            let Ok(metadata) = std::fs::symlink_metadata(child.path()) else {
                unexpected_child = true;
                break;
            };
            if !metadata.file_type().is_socket()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o777 != 0o600
            {
                unexpected_child = true;
                break;
            }
            socket_metadata = Some(metadata);
        }
        if unexpected_child || child_count > 1 {
            continue;
        }
        let socket_path = path.join(SOCKET_FILE_NAME);
        let socket_identity = socket_metadata.as_ref().map(FileIdentity::from_metadata);
        if socket_identity.is_some() {
            // A successful connection means a listener is alive. Any
            // ambiguous error also leaves the directory untouched.
            match connect_std_with_deadline(&socket_path, deadline) {
                Ok(stream) => {
                    let _ = attest_same_effective_uid(&stream);
                    continue;
                }
                Err(error) if is_definitely_stale_socket_error(&error) => {}
                Err(_) => continue,
            }
        }
        let Ok(rechecked_directory) = verify_runtime_directory(&path) else {
            continue;
        };
        if FileIdentity::from_metadata(&rechecked_directory) != directory_identity {
            continue;
        }
        if let Some(socket_identity) = socket_identity {
            let Ok(rechecked_socket) = std::fs::symlink_metadata(&socket_path) else {
                continue;
            };
            if FileIdentity::from_metadata(&rechecked_socket) != socket_identity {
                continue;
            }
            remove_if_identity_matches(&socket_path, Some(socket_identity), true);
        }
        remove_if_identity_matches(&path, Some(directory_identity), false);
    }
    Ok(())
}

fn is_runtime_directory_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(RUNTIME_DIRECTORY_PREFIX) else {
        return false;
    };
    suffix.len() == CHANNEL_DIRECTORY_HEX_LEN
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_definitely_stale_socket_error(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            )
        })
    })
}

fn verify_runtime_directory(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "audit-RPC runtime path is not a real directory"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "audit-RPC runtime directory is not owned by the effective user"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o700,
        "audit-RPC runtime directory mode is not 0700"
    );
    crate::util::darwin_acl::verify_directory_has_no_extended_acl(path).with_context(|| {
        format!(
            "verify audit-RPC runtime directory {} has no macOS extended ACL",
            path.display()
        )
    })?;
    Ok(metadata)
}

fn verify_socket(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_socket(),
        "audit-RPC endpoint is not a Unix socket"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "audit-RPC socket is not owned by the effective user"
    );
    ensure!(
        metadata.mode() & 0o777 == 0o600,
        "audit-RPC socket mode is not 0600"
    );
    Ok(metadata)
}

fn verify_endpoint_path(path: &Path, home_sha256: &str) -> Result<(FileIdentity, FileIdentity)> {
    let runtime_directory = path
        .parent()
        .context("audit-RPC Unix socket has no runtime directory")?;
    let home_namespace = runtime_directory
        .parent()
        .context("audit-RPC Unix runtime directory has no home namespace")?;
    verify_private_home_namespace(home_namespace, home_sha256)?;
    Ok((
        FileIdentity::from_metadata(&verify_runtime_directory(runtime_directory)?),
        FileIdentity::from_metadata(&verify_socket(path)?),
    ))
}

fn remove_if_identity_matches(path: &Path, expected: Option<FileIdentity>, socket: bool) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if expected.is_some_and(|identity| identity != FileIdentity::from_metadata(&metadata)) {
        return;
    }
    if socket {
        if metadata.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        }
    } else if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        let _ = std::fs::remove_dir(path);
    }
}

fn attest_same_effective_uid<T: AsRawFd>(stream: &T) -> Result<()> {
    attest_uid(stream, effective_uid())
}

pub(super) fn attest_uid<T: AsRawFd>(stream: &T, expected_uid: libc::uid_t) -> Result<()> {
    let peer = peer_uid(stream.as_raw_fd())?;
    ensure!(
        peer == expected_uid,
        "audit-RPC peer UID {peer} does not match expected UID {expected_uid}"
    );
    Ok(())
}

fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and no failure return.
    unsafe { libc::geteuid() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: std::os::fd::RawFd) -> Result<libc::uid_t> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` points to enough writable storage for `length`,
    // and `fd` is the live Unix stream owned by the caller.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    ensure!(
        length as usize == std::mem::size_of::<libc::ucred>(),
        "SO_PEERCRED returned an invalid credential length"
    );
    // SAFETY: getsockopt succeeded and initialized the complete ucred.
    Ok(unsafe { credentials.assume_init() }.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(fd: std::os::fd::RawFd) -> Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: the fd is a live connected Unix stream and both out-pointers
    // refer to initialized writable scalar storage.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("getpeereid");
    }
    Ok(uid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn peer_uid(_fd: std::os::fd::RawFd) -> Result<libc::uid_t> {
    anyhow::bail!("same-user Unix peer credentials are unsupported on this platform")
}
