//! PC-01 three-layer OS file-read gate: allowlist → autonomy → read + audit.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, Metadata, OpenOptions};

use crate::config::OsToolsConfig;
use crate::os_tools::allowlist::{
    AllowlistError, resolve_exec_program, resolve_within_allowlist, resolve_write_target,
};
use crate::os_tools::launch::launch_program;
use crate::os_tools::write::write_file_atomic;
#[cfg(test)]
use crate::permissions::AutonomyLevel;
use crate::permissions::{Action, Decision, PolicyArgument, evaluate};
use crate::wal::events::{
    EVENT_TYPE_OS_APP_LAUNCH, EVENT_TYPE_OS_APP_LAUNCH_DENIED, EVENT_TYPE_OS_FILE_DENIED,
    EVENT_TYPE_OS_FILE_READ, EVENT_TYPE_OS_FILE_WRITE, EVENT_TYPE_OS_FILE_WRITE_DENIED,
};
use crate::wal::writer::WalWriterHandle;

#[derive(Debug, thiserror::Error)]
pub enum OsGateError {
    #[error("OS file access denied (allowlist): {0}")]
    Allowlist(#[from] AllowlistError),
    #[error("OS file access denied by autonomy policy: {0}")]
    Denied(String),
    #[error("OS file access requires operator confirm (no interactive surface here): {0}")]
    ConfirmRequired(String),
    #[error("OS file read failed after gate passed: {0}")]
    ReadFailed(String),
    #[error("OS file read was stopped at typed PreToolUse: {0}")]
    PreToolUse(String),
    /// PC-01 write slice: the write content exceeds `max_write_bytes`.
    #[error("OS file write denied: {0}")]
    WriteTooLarge(String),
    /// PC-01 write slice: the write failed after the gate passed (IO error).
    #[error("OS file write failed after gate passed: {0}")]
    WriteFailed(String),
    /// PC-01 app-launch slice: the spawn failed after the gate passed (the
    /// binary vanished between resolution and spawn, exec perms, ENOMEM, …).
    #[error("OS app launch failed after gate passed: {0}")]
    LaunchFailed(String),
    /// PC-01 clipboard slice: the OS clipboard backend could not be opened —
    /// almost always a headless host with no display/clipboard server. The
    /// action is gated + audited (`0xBD`) exactly like any other refusal; this
    /// just distinguishes "policy refused" from "no backend here".
    #[error("OS clipboard backend unavailable (headless / no display?): {0}")]
    ClipboardUnavailable(String),
    /// PC-01 clipboard slice: a clipboard WRITE was refused because its content
    /// contains a newline/CR — the terminal auto-execute precondition of a
    /// pastejacking attack — and `tools.os.clipboard.allow_newlines_in_write` is
    /// off (the default). Fires structurally, BEFORE the autonomy gate.
    #[error("OS clipboard write denied (pastejacking guard): {0}")]
    PastejackingPattern(String),
    /// PC-01 clipboard slice: the clipboard content read back exceeds
    /// `max_clipboard_read_bytes`. Surfaced as a refusal (no oversize content is
    /// returned to the caller).
    #[error("OS clipboard read denied: {0}")]
    ReadTooLarge(String),
}

/// An opaque successful OS-file-read admission.  It is intentionally not a
/// path-shaped public capability: only this module can construct it, and the
/// follow-up invoke consumes the exact canonical target and byte ceiling that
/// passed the allowlist and autonomy checks.
#[derive(Debug)]
pub struct AdmittedOsFileRead {
    canonical: PathBuf,
    max_read_bytes: usize,
    file: std::fs::File,
}

/// An opaque admission for a directory-list operation. It owns a retained
/// no-follow directory capability, deliberately separate from `OsFileRead`.
#[derive(Debug)]
pub struct AdmittedOsDirectoryList {
    canonical: PathBuf,
    directory: Dir,
    identity: String,
}

impl AdmittedOsDirectoryList {
    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }

    /// Clone the retained directory capability for bounded child traversal.
    /// Callers receive no ambient path operation or file-read authority.
    pub fn directory(&self) -> std::io::Result<Dir> {
        self.directory.try_clone()
    }
    pub fn identity(&self) -> &str { &self.identity }
}

impl AdmittedOsFileRead {
    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }
}

/// Where a gated OS-tool action sends its WAL audit frame. Replaces the old
/// `Option<&WalWriterHandle>` so a one-shot CLI running while `neoth serve`
/// owns the single writer can still get its frame audited — by FORWARDING it
/// to the daemon over the same-user OS audit-RPC channel (AUDIT-RPC-01) instead of
/// silently dropping it.
#[derive(Clone, Copy)]
pub enum AuditSink<'a> {
    /// No audit (the action is still gated; the frame is simply not recorded).
    None,
    /// Append directly to a WAL writer this process owns (the daemon itself, or
    /// a one-shot CLI when no daemon is live).
    Writer(&'a WalWriterHandle),
    /// Append to a one-shot writer and retain the first append failure for the
    /// caller to enforce according to its configured required-audit posture.
    ///
    /// The gated action still returns its ordinary domain result. This keeps
    /// optional audit best-effort while allowing required CLI surfaces to
    /// refuse a false success after the action and writer finalization finish.
    TrackedWriter {
        writer: &'a WalWriterHandle,
        status: &'a AuditStatus,
    },
    /// Forward the frame to the live daemon's audit-RPC listener. `home` is the
    /// neoth home dir (used to find the sidecar + token). Best-effort: if the
    /// daemon/sidecar is unavailable the frame is dropped (same availability
    /// tradeoff as `None`), but the action already ran gated.
    DaemonRpc(&'a Path),
    /// Forward to the daemon and retain an exact acknowledgement failure for a
    /// required-audit caller. This closes the gap between a successful
    /// pre-flight probe and the later event dispatch.
    TrackedDaemonRpc {
        home: &'a Path,
        status: &'a AuditStatus,
    },
}

#[derive(Debug, Default)]
pub struct AuditStatus {
    first_failure: std::sync::Mutex<Option<String>>,
}

impl AuditStatus {
    fn record(&self, error: &crate::wal::error::WalError) {
        self.record_message(error.to_string());
    }

    fn record_message(&self, error: String) {
        let mut first_failure = self
            .first_failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if first_failure.is_none() {
            *first_failure = Some(error);
        }
    }

    pub fn failure(&self) -> Option<String> {
        self.first_failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

/// Send one audit frame to the chosen sink. Single source of truth for the
/// local-append vs daemon-forward dispatch — the per-event `emit_*` helpers
/// build the payload, this routes it.
async fn dispatch_frame(sink: AuditSink<'_>, event_type: u8, payload: Vec<u8>) {
    match sink {
        AuditSink::None => {}
        AuditSink::Writer(w) => {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let _ = w.append(header, payload).await;
        }
        AuditSink::TrackedWriter { writer, status } => {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            if let Err(error) = writer.append(header, payload).await {
                status.record(&error);
            }
        }
        AuditSink::DaemonRpc(home) => {
            // Same-user OS IPC to the WAL-owning daemon. Best-effort: a disabled
            // audit route or unreachable listener means the frame isn't
            // recorded (the action itself already happened, gated).
            if let Err(e) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
            {
                tracing::debug!(error = %e, event_type, "audit-RPC forward failed; frame not recorded");
            }
        }
        AuditSink::TrackedDaemonRpc { home, status } => {
            if let Err(error) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
            {
                status.record_message(error.to_string());
            }
        }
    }
}

/// The complete gated read: allowlist-validate `target`, run the autonomy
/// gate, read the (size-capped, UTF-8) file, and emit the WAL audit frame.
/// Returns the file text on success.
///
/// Every outcome is audited when `writer` is `Some`: `0xA8 OS_FILE_READ`
/// (with byte count) on success, `0xA9 OS_FILE_DENIED` (with reason) on any
/// allowlist / autonomy / read failure. `writer` is `None` only in contexts
/// that don't own a WAL writer (the daemon-single-writer rule); the read
/// itself is gated identically either way.
pub async fn read_os_file<P: PolicyArgument>(
    target: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    let admitted = preflight_os_file_read(target, cfg, policy, sink, now_unix).await?;
    invoke_preflighted_os_file_read(admitted, sink, now_unix).await
}

/// Run OS admission and bind one file descriptor without consuming its
/// contents.  This exists for the explicitly opt-in native PreToolUse route:
/// policy admits the exact target before the typed hook sees bounded metadata,
/// and the post-hook reader consumes this same descriptor rather than a path
/// that could have been swapped meanwhile.
pub async fn preflight_os_file_read<P: PolicyArgument>(
    target: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<AdmittedOsFileRead, OsGateError> {
    preflight_os_file_read_with_before_open(target, cfg, policy, sink, now_unix, |_| {}).await
}

/// Admit an allowlisted directory enumeration and retain an opened,
/// no-follow capability for its root. This does not open or read any files.
pub async fn preflight_os_directory_list<P: PolicyArgument>(
    target: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<AdmittedOsDirectoryList, OsGateError> {
    let canonical = match resolve_within_allowlist(target, &cfg.allowed_paths) {
        Ok(path) => path,
        Err(error) => {
            emit_denied(sink, &target.display().to_string(), &error.to_string(), now_unix).await;
            return Err(error.into());
        }
    };
    let action = Action::OsDirectoryList { path: canonical.clone() };
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_denied(sink, &canonical.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_denied(sink, &canonical.display().to_string(), &format!("confirm-required: {reason}"), now_unix).await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }
    let directory = open_absolute_directory_no_follow(&canonical).map_err(|error| {
        OsGateError::ReadFailed(format!("open directory {}: {error}", canonical.display()))
    })?;
    let identity = directory_identity(&directory)?;
    Ok(AdmittedOsDirectoryList { canonical, directory, identity })
}

fn directory_identity(directory: &Dir) -> Result<String, OsGateError> {
    #[cfg(unix)]
    {
        let metadata = directory.dir_metadata().map_err(|error| OsGateError::ReadFailed(error.to_string()))?;
        use cap_std::fs::MetadataExt as _;
        Ok(format!("unix:{:016x}:{:016x}", metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
        let size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(|error| OsGateError::ReadFailed(error.to_string()))?;
        // SAFETY: `directory` owns a live directory handle for this entire
        // call; `info` is writable `FILE_ID_INFO` storage and `size` is its
        // exact byte size, as required by FileIdInfo.
        if unsafe { GetFileInformationByHandleEx(directory.as_raw_handle() as _, FileIdInfo, info.as_mut_ptr().cast(), size) } == 0 {
            return Err(OsGateError::ReadFailed(std::io::Error::last_os_error().to_string()));
        }
        // SAFETY: a nonzero result above guarantees the complete FILE_ID_INFO
        // buffer was initialized by the OS before it is read here.
        let info = unsafe { info.assume_init() };
        if info.FileId.Identifier.iter().all(|byte| *byte == 0) { return Err(OsGateError::ReadFailed("directory handle has no stable file identity".into())); }
        Ok(format!("windows:{:08x}:{}", info.VolumeSerialNumber, info.FileId.Identifier.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
    }
    #[cfg(not(any(unix, windows)))]
    { Err(OsGateError::ReadFailed("no directory identity primitive on this platform".into())) }
}

pub(crate) fn current_directory_identity_no_follow(path: &Path) -> Result<String, OsGateError> {
    let directory = open_absolute_directory_no_follow(path).map_err(|error| OsGateError::ReadFailed(error.to_string()))?;
    directory_identity(&directory)
}

async fn preflight_os_file_read_with_before_open<P: PolicyArgument>(
    target: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
    before_open: impl FnOnce(&Path),
) -> Result<AdmittedOsFileRead, OsGateError> {
    // Layer 1 — allowlist + traversal (fail-closed).
    let canonical = match resolve_within_allowlist(target, &cfg.allowed_paths) {
        Ok(c) => c,
        Err(e) => {
            emit_denied(
                sink,
                &target.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate (the path is already allowlist-validated).
    let action = Action::OsFileRead {
        path: canonical.clone(),
    };
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_denied(sink, &canonical.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            // The OS-tool path has no TTY/operator prompt — a Confirm
            // verdict (Strict) fails closed, audited, with the reason.
            emit_denied(
                sink,
                &canonical.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    before_open(&canonical);
    let file = match open_no_follow_read_descriptor(&canonical) {
        Ok(file) => file,
        Err(error) => {
            let reason = format!("open {}: {error}", canonical.display());
            emit_denied(sink, &canonical.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::ReadFailed(reason));
        }
    };
    Ok(AdmittedOsFileRead {
        canonical,
        max_read_bytes: cfg.max_read_bytes,
        file,
    })
}

/// Resolve an already-canonical target from pinned directory handles.  Every
/// parent component and the final leaf is opened without following a link or
/// reparse point, so an attacker cannot replace a namespace entry during the
/// audit await and redirect the descriptor outside the allowed object.
fn open_no_follow_read_descriptor(canonical: &Path) -> std::io::Result<std::fs::File> {
    let parent_path = canonical.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file target has no parent",
        )
    })?;
    let leaf = canonical.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file target has no leaf")
    })?;
    let parent = open_absolute_directory_no_follow(parent_path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no no-follow filesystem descriptor primitive on this platform",
    ));

    let file = parent.open_with(leaf, &options)?.into_std();
    let metadata = file.metadata()?;
    if metadata_is_link_or_reparse(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target is a symlink or reparse point",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_read_capability_root(path: &Path) -> std::io::Result<PathBuf> {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "absolute Windows path has no filesystem prefix",
        ));
    };
    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
    ) || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported or relative Windows filesystem namespace",
        ));
    }
    // Preserve the exact drive/share and canonical verbatim namespace. A UNC
    // allowlist remains usable; device/pipe namespaces never become file roots.
    Ok(path.components().take(2).collect())
}

pub(crate) fn open_absolute_directory_no_follow(path: &Path) -> std::io::Result<Dir> {
    #[cfg(unix)]
    let mut current = Dir::open_ambient_dir(Path::new("/"), cap_std::ambient_authority())?;
    #[cfg(windows)]
    let mut current = Dir::open_ambient_dir(
        windows_read_capability_root(path)?,
        cap_std::ambient_authority(),
    )?;
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no no-follow directory primitive on this platform",
    ));

    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let observed = current.symlink_metadata(name)?;
        if cap_metadata_is_link_or_reparse(&observed) || !observed.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path parent is a symlink, reparse point, or non-directory",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options
                .access_mode(FILE_GENERIC_READ)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let next = current.open_with(name, &options)?.into_std();
        let metadata = next.metadata()?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opened parent is a symlink, reparse point, or non-directory",
            ));
        }
        current = Dir::from_std_file(next);
    }
    Ok(current)
}

fn metadata_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

/// The capability-directory equivalent of [`metadata_is_link_or_reparse`].
/// `Dir::symlink_metadata` deliberately reports the namespace entry itself,
/// so this check happens before opening every next parent component.
fn cap_metadata_is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Open one child directory from an already admitted capability without
/// following a link/reparse point. This closes the check/open race that a
/// `DirEntry::open_dir()` convenience call would otherwise leave to ambient
/// platform semantics.
pub fn open_child_directory_no_follow(parent: &Dir, child: &Path) -> std::io::Result<Dir> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options.access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no no-follow child directory primitive on this platform"));
    let opened = parent.open_with(child, &options)?.into_std();
    let metadata = opened.metadata()?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "child is a link, reparse point, or non-directory"));
    }
    Ok(Dir::from_std_file(opened))
}

/// Consume one successful preflight and perform the bounded same-fd read.
/// There is no path input here, so a caller cannot switch targets between its
/// PreToolUse decision and the actual file operation.
pub async fn invoke_preflighted_os_file_read(
    admitted: AdmittedOsFileRead,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    match read_open_file_text(admitted.file, &admitted.canonical, admitted.max_read_bytes) {
        Ok(text) => {
            emit_read(
                sink,
                &admitted.canonical.display().to_string(),
                text.len(),
                now_unix,
            )
            .await;
            Ok(text)
        }
        Err(e) => {
            emit_denied(
                sink,
                &admitted.canonical.display().to_string(),
                &format!("read-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::ReadFailed(e.to_string()))
        }
    }
}

/// The existing OS reader's regular-file and hard byte bound, applied to the
/// descriptor held by [`AdmittedOsFileRead`].  Keeping the stat and read on
/// this descriptor prevents an accepted path from being replaced while the
/// bounded PreToolUse hook executes.
fn read_open_file_text(
    file: std::fs::File,
    canonical: &Path,
    max_bytes: usize,
) -> Result<String, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", canonical.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{} is not a regular file — pipes, devices, directories and /proc entries are refused",
            canonical.display()
        ));
    }
    let length = metadata.len();
    if length > max_bytes as u64 {
        return Err(format!(
            "file {} is {length} bytes, exceeds tools.os.max_read_bytes={max_bytes}",
            canonical.display()
        ));
    }
    let mut bytes = Vec::with_capacity(length.min(max_bytes as u64) as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", canonical.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "file {} exceeded tools.os.max_read_bytes={max_bytes} during read (grew after stat?)",
            canonical.display()
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        format!(
            "{} is not valid UTF-8 (binary file?): {error}",
            canonical.display()
        )
    })
}

/// The complete gated WRITE (PC-01 write slice): size-cap → write-allowlist →
/// autonomy gate (Strict deny / Standard confirm / Elevated+Full allow) →
/// atomic write → WAL audit (`0xAA OS_FILE_WRITE` on success, `0xAB
/// OS_FILE_WRITE_DENIED` on any refusal/failure). Returns the resolved path
/// written on success.
pub async fn write_os_file<P: PolicyArgument>(
    target: &Path,
    contents: &[u8],
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<PathBuf, OsGateError> {
    // Layer 0 — size cap BEFORE any path work (cheap reject of an oversize write).
    if contents.len() > cfg.max_write_bytes {
        let reason = format!(
            "content {} bytes exceeds max_write_bytes {}",
            contents.len(),
            cfg.max_write_bytes
        );
        emit_write_denied(sink, &target.display().to_string(), &reason, now_unix).await;
        return Err(OsGateError::WriteTooLarge(reason));
    }

    // Layer 1 — write-allowlist (canonical parent under allowed_write_paths;
    // symlink-escape + traversal rejected; fail-closed).
    let resolved = match resolve_write_target(target, &cfg.allowed_write_paths) {
        Ok(p) => p,
        Err(e) => {
            emit_write_denied(
                sink,
                &target.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate.
    let action = Action::OsFileWrite {
        path: resolved.clone(),
    };
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_write_denied(sink, &resolved.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_write_denied(
                sink,
                &resolved.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — GOLD-LF-P1-01: durable intent BEFORE the effect. Everything
    // above this line only ever refused a write; from here on a write can
    // actually happen, so this is the last point at which the WAL can still
    // learn what we were about to do. Fail closed: if the intent cannot be
    // recorded we do not write, because the alternative is a file on disk that
    // no audit trail explains.
    let resolved_display = resolved.display().to_string();
    let id = crate::wal::events::next_intent_id(b"os-file-write", &resolved_display, now_unix);
    if !emit_write_intent(sink, &id, &resolved_display, contents, now_unix)
        .await
        .permits_effect()
    {
        let reason = "mandatory pre-write audit intent could not be recorded".to_string();
        emit_write_denied(sink, &resolved_display, &reason, now_unix).await;
        return Err(OsGateError::Denied(reason));
    }

    // Layer 4 — atomic write + audit. `existed` records whether we overwrote.
    let existed = resolved.exists();
    match write_file_atomic(&resolved, contents) {
        Ok(()) => {
            emit_write_result(sink, &id, "written", None, now_unix).await;
            emit_write(sink, &resolved_display, contents.len(), existed, now_unix).await;
            Ok(resolved)
        }
        Err(e) => {
            emit_write_result(sink, &id, "failed", Some(&e.to_string()), now_unix).await;
            emit_write_denied(
                sink,
                &resolved_display,
                &format!("write-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::WriteFailed(e.to_string()))
        }
    }
}

/// The complete gated LAUNCH (PC-01 app-launch slice): exec-allowlist (exact
/// canonical match against `allowed_exec_paths`) → autonomy gate (Strict deny /
/// Standard+Elevated confirm / Full allow) → spawn (no args, no shell, detached
/// stdio) → WAL audit (`0xAC OS_APP_LAUNCH` on success, `0xAD
/// OS_APP_LAUNCH_DENIED` on any refusal/failure). Returns the resolved program
/// path + the launched PID on success.
pub async fn launch_os_app<P: PolicyArgument>(
    program: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<(PathBuf, u32), OsGateError> {
    // Layer 1 — exec-allowlist (exact canonical match; regular-file-only; fail-closed).
    let resolved = match resolve_exec_program(program, &cfg.allowed_exec_paths) {
        Ok(p) => p,
        Err(e) => {
            emit_launch_denied(
                sink,
                &program.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate (the program is already allowlist-validated).
    let action = Action::OsAppLaunch {
        program: resolved.clone(),
    };
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_launch_denied(sink, &resolved.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_launch_denied(
                sink,
                &resolved.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — GOLD-LF-P1-01: durable intent BEFORE the spawn. A process that
    // started while its success frame was still in flight used to leave no
    // record at all; the intent is what makes that window visible.
    let resolved_display = resolved.display().to_string();
    let id = crate::wal::events::next_intent_id(b"os-app-launch", &resolved_display, now_unix);
    if !emit_launch_intent(sink, &id, &resolved_display, now_unix)
        .await
        .permits_effect()
    {
        let reason = "mandatory pre-launch audit intent could not be recorded".to_string();
        emit_launch_denied(sink, &resolved_display, &reason, now_unix).await;
        return Err(OsGateError::Denied(reason));
    }

    // Layer 4 — spawn + audit.
    match launch_program(&resolved) {
        Ok(pid) => {
            emit_launch_result(sink, &id, "launched", Some(pid), None, now_unix).await;
            emit_launch(sink, &resolved_display, pid, now_unix).await;
            Ok((resolved, pid))
        }
        Err(e) => {
            emit_launch_result(sink, &id, "failed", None, Some(&e.to_string()), now_unix).await;
            emit_launch_denied(
                sink,
                &resolved_display,
                &format!("launch-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::LaunchFailed(e.to_string()))
        }
    }
}

/// Characters that act as a LINE TERMINATOR in a terminal — the AUTO-EXECUTE
/// precondition a pastejacking clipboard write needs. Beyond ASCII `\n`/`\r`
/// this includes NEL (U+0085), LINE SEPARATOR (U+2028), and PARAGRAPH SEPARATOR
/// (U+2029), which some terminals also honour and whose UTF-8 encodings contain
/// no 0x0A/0x0D byte (so a `bytes()`-level scan would miss them).
#[cfg(feature = "os-clipboard")]
fn is_clipboard_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}

/// PC-01 (clipboard slice) — the complete gated clipboard READ. Layers, in
/// order: (-1) runtime kill-switches (`clipboard.enabled` + `read_enabled`),
/// (2) autonomy gate (`OsClipboardRead`: Strict deny / Standard + Elevated
/// confirm ⇒ fail-closed here / Full allow), (1) open the backend (graceful on
/// headless), (0) size cap on the value read back. Every refusal AND the success
/// emit `0xBC`/`0xBD` carrying ONLY `{op, bytes|reason, ts_unix}` — the clipboard
/// CONTENT is never in any frame, log, or error. Returns the text on success.
#[cfg(feature = "os-clipboard")]
pub async fn read_os_clipboard<P: PolicyArgument>(
    cfg: &crate::config::ClipboardConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    // Layer -1 — runtime kill-switches (master + read sub-toggle). Fail-closed,
    // and a disabled surface NEVER touches the clipboard backend.
    if !cfg.enabled {
        let reason = "clipboard disabled (freedom.yaml::tools.os.clipboard.enabled=false)";
        emit_clipboard_denied(sink, "read", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    if !cfg.read_enabled {
        let reason =
            "clipboard read disabled (freedom.yaml::tools.os.clipboard.read_enabled=false)";
        emit_clipboard_denied(sink, "read", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    // Layer 2 — autonomy gate, BEFORE touching the backend: a denied read must
    // never open the clipboard.
    let action = Action::OsClipboardRead;
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_clipboard_denied(sink, "read", &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_clipboard_denied(
                sink,
                "read",
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }
    // Layer 1 — open the backend + read. Graceful on headless / no-display. The
    // value is held in a `Zeroizing` buffer so a clipboard SECRET that the size
    // cap (or any error below) then rejects is WIPED from the heap on drop rather
    // than lingering in freed memory.
    let text = match crate::os_tools::clipboard::read_clipboard_text() {
        Ok(t) => zeroize::Zeroizing::new(t),
        Err(e) => {
            emit_clipboard_denied(sink, "read", "clipboard-backend-unavailable", now_unix).await;
            return Err(OsGateError::ClipboardUnavailable(e.to_string()));
        }
    };
    // Layer 0 (post-read) — size cap: never surface an oversize clipboard value.
    // The WAL reason is a STATIC tag; the byte-count detail lives only in the
    // returned error, never in the audit frame. (`text` wipes on the early drop.)
    if text.len() > cfg.max_clipboard_read_bytes {
        emit_clipboard_denied(sink, "read", "read-too-large", now_unix).await;
        return Err(OsGateError::ReadTooLarge(format!(
            "clipboard content {} bytes exceeds max_clipboard_read_bytes {}",
            text.len(),
            cfg.max_clipboard_read_bytes
        )));
    }
    // Layer 3 — audit (byte COUNT only — content never in the frame) + return.
    // The returned copy is the operator's (they invoked the read); the backend
    // buffer (`text`) wipes on drop at the end of this function.
    emit_clipboard_access(sink, "read", text.len(), now_unix).await;
    Ok(text.to_string())
}

/// PC-01 (clipboard slice) — the complete gated clipboard WRITE. Layers: (-1)
/// kill-switches (`enabled` + `write_enabled`), (0) size cap, (0b) pastejacking
/// newline guard (STRUCTURAL — fires at EVERY autonomy level, even Full, unless
/// `allow_newlines_in_write`), (2) autonomy gate (`OsClipboardWrite`: Strict +
/// Standard deny / Elevated confirm ⇒ fail-closed / Full allow), (1+3) write +
/// audit. `0xBC`/`0xBD` carry only `{op, bytes|reason, ts_unix}` — never content.
/// Returns the byte count written on success.
#[cfg(feature = "os-clipboard")]
pub async fn write_os_clipboard<P: PolicyArgument>(
    content: &str,
    cfg: &crate::config::ClipboardConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<usize, OsGateError> {
    // Layer -1 — kill-switches.
    if !cfg.enabled {
        let reason = "clipboard disabled (freedom.yaml::tools.os.clipboard.enabled=false)";
        emit_clipboard_denied(sink, "write", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    if !cfg.write_enabled {
        let reason =
            "clipboard write disabled (freedom.yaml::tools.os.clipboard.write_enabled=false)";
        emit_clipboard_denied(sink, "write", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    // Layer 0 — size cap (cheap reject before anything else). STATIC WAL reason;
    // the byte-count detail lives only in the returned error, never the frame.
    if content.len() > cfg.max_clipboard_write_bytes {
        emit_clipboard_denied(sink, "write", "write-too-large", now_unix).await;
        return Err(OsGateError::WriteTooLarge(format!(
            "content {} bytes exceeds max_clipboard_write_bytes {}",
            content.len(),
            cfg.max_clipboard_write_bytes
        )));
    }
    // Layer 0a — control-character guard. ALWAYS rejected (independent of
    // autonomy AND of `allow_newlines_in_write`): ESC + the other C0/C1 control
    // characters have no legitimate place in clipboard TEXT and are the building
    // blocks of terminal-escape / bracketed-paste-escape injections (e.g.
    // `\x1b[201~…` closes paste mode so the trailing bytes auto-execute) that
    // would otherwise sail straight past the line-terminator guard. Tab is the
    // sole permitted control character; line terminators are handled in Layer 0b.
    if let Some(c) = content
        .chars()
        .find(|&c| c.is_control() && c != '\t' && !is_clipboard_line_terminator(c))
    {
        emit_clipboard_denied(sink, "write", "control-character-in-write", now_unix).await;
        return Err(OsGateError::PastejackingPattern(format!(
            "control character U+{:04X} not permitted in a clipboard write \
             (terminal-escape / paste-injection guard)",
            c as u32
        )));
    }
    // Layer 0b — pastejacking LINE-TERMINATOR guard. A line terminator is the
    // terminal AUTO-EXECUTE precondition. This covers not only `\n`/`\r` but the
    // Unicode line terminators NEL (U+0085), LS (U+2028), PS (U+2029) that some
    // terminals also act on and whose UTF-8 encodings contain no 0x0A/0x0D byte
    // (so a `bytes()`-only check would miss them). Rejected STRUCTURALLY at every
    // autonomy level (audited) unless the operator opts in.
    let has_line_terminator = content.chars().any(is_clipboard_line_terminator);
    if has_line_terminator && !cfg.allow_newlines_in_write {
        emit_clipboard_denied(sink, "write", "line-terminator-in-write", now_unix).await;
        return Err(OsGateError::PastejackingPattern(
            "content contains a line terminator (\\n / \\r / NEL / U+2028 / U+2029 — the terminal \
             auto-execute precondition); set tools.os.clipboard.allow_newlines_in_write=true to \
             permit multi-line writes"
                .into(),
        ));
    }
    // Layer 2 — autonomy gate.
    let action = Action::OsClipboardWrite;
    let policy_snapshot = policy.policy_snapshot();
    let decision = evaluate(&action, policy);
    emit_trust_decision(sink, &action, policy_snapshot.level(), &decision, now_unix).await;
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_clipboard_denied(sink, "write", &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_clipboard_denied(
                sink,
                "write",
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }
    // Observability (Lens 3 advisory): a permitted multi-line write still carries
    // pastejacking risk; surface it for the operator's audit trail.
    if has_line_terminator {
        tracing::warn!(
            "OS clipboard write contains a line terminator (allow_newlines_in_write=true) — \
             pastejacking risk acknowledged by config"
        );
    }
    // Layer 1+3 — open the backend (graceful), write, audit (byte count only).
    match crate::os_tools::clipboard::write_clipboard_text(content) {
        Ok(()) => {
            emit_clipboard_access(sink, "write", content.len(), now_unix).await;
            Ok(content.len())
        }
        Err(e) => {
            emit_clipboard_denied(sink, "write", "clipboard-backend-unavailable", now_unix).await;
            Err(OsGateError::ClipboardUnavailable(e.to_string()))
        }
    }
}

async fn emit_launch(sink: AuditSink<'_>, program: &str, pid: u32, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "program": program,
        "pid": pid,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_APP_LAUNCH, payload).await;
}

async fn emit_launch_denied(sink: AuditSink<'_>, program: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "program": program,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_APP_LAUNCH_DENIED, payload).await;
}

/// GOLD-LF-P1-01. What happened to a mandatory intent frame.
///
/// The three-way split exists because "the frame did not land" has two
/// materially different causes, and collapsing them would either break working
/// installations or quietly weaken the guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentOutcome {
    /// The frame is durable in a WAL this process owns, or auditing is
    /// deliberately disabled (`AuditSink::None`). Safe to perform the effect.
    Recorded,
    /// The sink is the audit-RPC forward and no daemon was reachable.
    /// AUDIT-RPC-01 ratified that an unreachable forwarder must NOT fail the
    /// action, so this still permits the effect — but it is a real hole in the
    /// pre-mutation trail, not a success, and it is named as such.
    ForwardUnavailable,
    /// An authoritative sink rejected the append. The effect must not happen:
    /// this is the case where proceeding would leave a mutation that no audit
    /// trail explains.
    Failed,
}

impl IntentOutcome {
    /// AUDIT-RPC-01 keeps the best-effort forward permissive; only an
    /// authoritative sink failure blocks.
    fn permits_effect(self) -> bool {
        !matches!(self, IntentOutcome::Failed)
    }
}

/// GOLD-LF-P1-01. Like [`dispatch_frame`], but for an EXTENDED `(0x00,
/// subtype)` pair, and it *reports* what happened instead of swallowing the
/// error, so a caller can refuse a mutation whose intent could not be recorded.
async fn dispatch_extended_frame(
    sink: AuditSink<'_>,
    subtype: crate::wal::events::ExtendedSubtype,
    payload: Vec<u8>,
) -> IntentOutcome {
    let code = subtype as u8;
    match sink {
        AuditSink::None => IntentOutcome::Recorded,
        AuditSink::Writer(w) => {
            let header = crate::wal::HeaderBuilder::new(0x00, &payload)
                .event_subtype(code)
                .build();
            let append = if subtype == crate::wal::events::ExtendedSubtype::TrustDecision {
                w.append_authenticated(header, payload).await
            } else {
                w.append(header, payload).await
            };
            match append {
                Ok(_) => IntentOutcome::Recorded,
                Err(_) => IntentOutcome::Failed,
            }
        }
        AuditSink::TrackedWriter { writer, status } => {
            let header = crate::wal::HeaderBuilder::new(0x00, &payload)
                .event_subtype(code)
                .build();
            let append = if subtype == crate::wal::events::ExtendedSubtype::TrustDecision {
                writer.append_authenticated(header, payload).await
            } else {
                writer.append(header, payload).await
            };
            match append {
                Ok(_) => IntentOutcome::Recorded,
                Err(error) => {
                    status.record(&error);
                    IntentOutcome::Failed
                }
            }
        }
        AuditSink::DaemonRpc(home) => {
            match crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
                home, 0x00, code, &payload,
            )
            .await
            {
                Ok(()) => IntentOutcome::Recorded,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        subtype = code,
                        "pre-mutation audit intent could not be forwarded; \
                         effect proceeds unaudited per AUDIT-RPC-01"
                    );
                    IntentOutcome::ForwardUnavailable
                }
            }
        }
        AuditSink::TrackedDaemonRpc { home, status } => {
            match crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
                home, 0x00, code, &payload,
            )
            .await
            {
                Ok(()) => IntentOutcome::Recorded,
                Err(error) => {
                    status.record_message(error.to_string());
                    IntentOutcome::ForwardUnavailable
                }
            }
        }
    }
}

/// Append the closed, metadata-only projection of the policy result while
/// preserving the OS-specific lifecycle frames emitted by the caller. A
/// tracked sink retains append failures for the existing required-audit owner;
/// an ordinary sink keeps its documented best-effort behavior.
async fn emit_trust_decision(
    sink: AuditSink<'_>,
    action: &Action,
    autonomy: crate::permissions::AutonomyLevel,
    decision: &Decision,
    now_unix: i64,
) {
    let event = match crate::permissions::TrustEvent::from_resolved_decision(
        action,
        autonomy,
        decision,
        None,
        None,
        None,
        None,
        now_unix.max(0) as u64 * 1_000_000_000,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(error = %error, action = ?action, "refused to encode typed OS trust decision");
            return;
        }
    };
    let payload = match event.encode() {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(error = %error, action = ?action, "refused to serialize typed OS trust decision");
            return;
        }
    };
    let _ = dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::TrustDecision,
        payload,
    )
    .await;
}

/// GOLD-LF-P1-01 — durable record of a write we are *about* to perform. The
/// contents never enter the WAL; they are bound by digest so the result frame
/// (and a later forensic read of the file) can be tied to this exact intent.
async fn emit_write_intent(
    sink: AuditSink<'_>,
    intent_id: &str,
    path: &str,
    contents: &[u8],
    ts_unix: i64,
) -> IntentOutcome {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "path": path,
        "bytes": contents.len(),
        "contents_sha256": crate::wal::events::effect_digest(b"os-file-write", contents),
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsFileWriteIntent,
        payload,
    )
    .await
}

/// GOLD-LF-P1-01 — terminal outcome for one [`emit_write_intent`]. An intent
/// with no matching result is exactly the crash window this pair exists to
/// make visible.
async fn emit_write_result(
    sink: AuditSink<'_>,
    intent_id: &str,
    outcome: &str,
    detail: Option<&str>,
    ts_unix: i64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "detail": detail,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let _ = dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsFileWriteResult,
        payload,
    )
    .await;
}

/// GOLD-LF-P1-01 — durable record of a launch we are *about* to perform.
async fn emit_launch_intent(
    sink: AuditSink<'_>,
    intent_id: &str,
    program: &str,
    ts_unix: i64,
) -> IntentOutcome {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "program": program,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsAppLaunchIntent,
        payload,
    )
    .await
}

/// GOLD-LF-P1-01 — terminal outcome for one [`emit_launch_intent`], carrying
/// the PID so a forensic reader can tie the intent to a real process.
async fn emit_launch_result(
    sink: AuditSink<'_>,
    intent_id: &str,
    outcome: &str,
    pid: Option<u32>,
    detail: Option<&str>,
    ts_unix: i64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "pid": pid,
        "detail": detail,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let _ = dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsAppLaunchResult,
        payload,
    )
    .await;
}

async fn emit_write(sink: AuditSink<'_>, path: &str, bytes: usize, existed: bool, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "existed": existed,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_WRITE, payload).await;
}

async fn emit_write_denied(sink: AuditSink<'_>, path: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_WRITE_DENIED, payload).await;
}

async fn emit_read(sink: AuditSink<'_>, path: &str, bytes: usize, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_READ, payload).await;
}

async fn emit_denied(sink: AuditSink<'_>, path: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_DENIED, payload).await;
}

/// PC-01 clipboard — success audit (`0xBC`). **CONTENT IS NEVER A PARAMETER** —
/// only the operation (`read`/`write`) + the byte COUNT. This is the load-bearing
/// no-exfil invariant: a clipboard frequently holds a just-copied secret, so the
/// frame must carry metadata only.
#[cfg(feature = "os-clipboard")]
async fn emit_clipboard_access(sink: AuditSink<'_>, op: &str, bytes: usize, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "op": op,
        "bytes": bytes,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(
        sink,
        crate::wal::events::EVENT_TYPE_OS_CLIPBOARD_ACCESS,
        payload,
    )
    .await;
}

/// PC-01 clipboard — denial audit (`0xBD`). `reason` is a policy/diagnostic
/// string (+ byte counts) — NEVER the clipboard content.
#[cfg(feature = "os-clipboard")]
async fn emit_clipboard_denied(sink: AuditSink<'_>, op: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "op": op,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(
        sink,
        crate::wal::events::EVENT_TYPE_OS_CLIPBOARD_DENIED,
        payload,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn cfg_for(dir: &Path) -> OsToolsConfig {
        let canonical_dir = dir.canonicalize().unwrap();
        OsToolsConfig {
            allowed_paths: vec![canonical_dir.clone()],
            max_read_bytes: 1024 * 1024,
            allowed_write_paths: vec![canonical_dir],
            max_write_bytes: 1024 * 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        }
    }

    #[tokio::test]
    async fn write_allowlisted_file_at_elevated_then_read_back() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("out.txt");
        let cfg = cfg_for(dir.path());
        // Elevated ⇒ OsFileWrite is Allow.
        let resolved = write_os_file(
            &f,
            b"written",
            &cfg,
            AutonomyLevel::Elevated,
            AuditSink::None,
            0,
        )
        .await
        .expect("elevated write under allowlist must succeed");
        assert!(resolved.ends_with("out.txt"));
        assert_eq!(fs::read(&f).unwrap(), b"written");
    }

    #[tokio::test]
    async fn write_denied_at_standard_no_tty() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        // Standard ⇒ OsFileWrite is Confirm ⇒ no TTY ⇒ ConfirmRequired.
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn write_denied_at_strict() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Strict,
            AuditSink::None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::Denied(_))));
    }

    #[tokio::test]
    async fn write_deny_all_when_no_write_allowlist() {
        let dir = tempdir().unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![dir.path().to_path_buf()],
            max_read_bytes: 1024,
            allowed_write_paths: vec![], // deny-all writes
            max_write_bytes: 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::None,
            0,
        )
        .await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn write_too_large_is_rejected() {
        let dir = tempdir().unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![dir.path().to_path_buf()],
            max_read_bytes: 1024,
            allowed_write_paths: vec![dir.path().to_path_buf()],
            max_write_bytes: 4,
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"way too long",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::WriteTooLarge(_))));
    }

    #[tokio::test]
    async fn reads_allowlisted_file_at_standard() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"hello-os").unwrap();
        let cfg = cfg_for(dir.path());
        let text = read_os_file(&f, &cfg, AutonomyLevel::Standard, AuditSink::None, 0)
            .await
            .unwrap();
        assert_eq!(text, "hello-os");
    }

    #[tokio::test]
    async fn read_preflight_binds_descriptor_then_invoke_enforces_same_fd_budget() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("budget.txt");
        fs::write(&file, b"12345").unwrap();
        let mut cfg = cfg_for(dir.path());
        cfg.max_read_bytes = 4;

        let admitted =
            preflight_os_file_read(&file, &cfg, AutonomyLevel::Standard, AuditSink::None, 0)
                .await
                .expect("policy admission binds but does not consume the file");
        assert_eq!(admitted.canonical_path(), file.canonicalize().unwrap());
        assert!(matches!(
            invoke_preflighted_os_file_read(admitted, AuditSink::None, 0).await,
            Err(OsGateError::ReadFailed(reason)) if reason.contains("exceeds")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn read_capability_root_preserves_windows_drive_and_share_namespaces() {
        for (path, expected) in [
            (r"C:\allowed\file.txt", r"C:\"),
            (r"\\?\C:\allowed\file.txt", r"\\?\C:\"),
            (r"\\server\share\allowed\file.txt", r"\\server\share\"),
            (
                r"\\?\UNC\server\share\allowed\file.txt",
                r"\\?\UNC\server\share\",
            ),
        ] {
            assert_eq!(
                windows_read_capability_root(Path::new(path)).unwrap(),
                PathBuf::from(expected),
            );
        }
        for path in [
            r"C:relative.txt",
            r"\rooted-without-drive",
            r"\\.\pipe\private",
        ] {
            assert!(windows_read_capability_root(Path::new(path)).is_err());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn preflight_reads_canonicalized_windows_drive_path() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("windows-drive.txt");
        fs::write(&file, b"canonical Windows path\n").unwrap();
        let canonical_file = file.canonicalize().unwrap();
        let cfg = cfg_for(dir.path());

        let admitted = preflight_os_file_read(
            &canonical_file,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::None,
            0,
        )
        .await
        .expect("canonicalized drive paths retain their verbatim root");
        let text = invoke_preflighted_os_file_read(admitted, AuditSink::None, 0)
            .await
            .unwrap();
        assert_eq!(text, "canonical Windows path\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admitted_read_consumes_original_descriptor_after_path_replaced() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let replacement = dir.path().join("replacement.txt");
        fs::write(&target, b"accepted descriptor\n").unwrap();
        fs::write(&replacement, b"replacement path\n").unwrap();
        let cfg = cfg_for(dir.path());
        let admitted =
            preflight_os_file_read(&target, &cfg, AutonomyLevel::Standard, AuditSink::None, 0)
                .await
                .unwrap();
        fs::rename(&replacement, &target).unwrap();
        let text = invoke_preflighted_os_file_read(admitted, AuditSink::None, 0)
            .await
            .unwrap();
        assert_eq!(text, "accepted descriptor\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preflight_refuses_final_symlink_swap_before_descriptor_open() {
        use std::os::unix::fs::symlink;

        let allowed = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = allowed.path().join("target.txt");
        let moved_target = allowed.path().join("target-before-swap.txt");
        let secret = outside.path().join("secret.txt");
        fs::write(&target, b"allowlisted before swap\n").unwrap();
        fs::write(&secret, b"outside allowlist\n").unwrap();
        let cfg = cfg_for(allowed.path());

        let result = preflight_os_file_read_with_before_open(
            &target,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::None,
            0,
            |canonical| {
                fs::rename(canonical, &moved_target).unwrap();
                symlink(&secret, canonical).unwrap();
            },
        )
        .await;

        assert!(matches!(result, Err(OsGateError::ReadFailed(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preflight_refuses_parent_symlink_swap_before_descriptor_open() {
        use std::os::unix::fs::symlink;

        let allowed = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let contained = allowed.path().join("contained");
        let moved_contained = allowed.path().join("contained-before-swap");
        let target = contained.join("target.txt");
        let outside_target = outside.path().join("target.txt");
        fs::create_dir(&contained).unwrap();
        fs::write(&target, b"allowlisted before parent swap\n").unwrap();
        fs::write(&outside_target, b"outside allowlist\n").unwrap();
        let cfg = cfg_for(allowed.path());

        let result = preflight_os_file_read_with_before_open(
            &target,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::None,
            0,
            |_| {
                fs::rename(&contained, &moved_contained).unwrap();
                symlink(outside.path(), &contained).unwrap();
            },
        )
        .await;

        assert!(matches!(result, Err(OsGateError::ReadFailed(_))));
    }

    #[tokio::test]
    async fn deny_all_when_no_allowlist() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![],
            max_read_bytes: 1024,
            allowed_write_paths: vec![],
            max_write_bytes: 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = read_os_file(&f, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn daemon_rpc_sink_without_listener_is_graceful_noop() {
        // AUDIT-RPC-01 Commit-2: when the sink is DaemonRpc but no daemon /
        // sidecar is reachable, the audit frame is silently dropped (best-effort)
        // — the gated read STILL succeeds. The action must never fail just
        // because audit forwarding is unavailable.
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"forwarded-or-not").unwrap();
        let cfg = cfg_for(dir.path());
        let home = tempdir().unwrap(); // no sidecar here ⇒ forward is Unavailable
        let text = read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::DaemonRpc(home.path()),
            0,
        )
        .await
        .expect("read must succeed even when audit-RPC forwarding is unavailable");
        assert_eq!(text, "forwarded-or-not");
    }

    #[tokio::test]
    async fn tracked_daemon_rpc_retains_exact_forward_failure() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"forwarded-or-not").unwrap();
        let cfg = cfg_for(dir.path());
        let home = tempdir().unwrap();
        let status = AuditStatus::default();

        let text = read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::TrackedDaemonRpc {
                home: home.path(),
                status: &status,
            },
            0,
        )
        .await
        .expect("domain action remains separate from the caller's required-audit policy");

        assert_eq!(text, "forwarded-or-not");
        assert!(
            status.failure().is_some(),
            "tracked daemon sink must retain the exact acknowledgement failure"
        );
    }

    #[tokio::test]
    async fn tracked_writer_retains_append_failure_for_required_caller() {
        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(segment).expect("spawn test writer");
        join.abort();
        let _ = join.await;
        let status = AuditStatus::default();

        dispatch_frame(
            AuditSink::TrackedWriter {
                writer: &writer,
                status: &status,
            },
            crate::wal::events::EVENT_TYPE_OS_APP_LAUNCH,
            br#"{"program":"test"}"#.to_vec(),
        )
        .await;

        assert!(
            status.failure().is_some(),
            "tracked sink must retain the append failure for the required-audit caller"
        );
    }

    #[tokio::test]
    async fn traversal_is_denied_even_at_full() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let evil = dir.path().join("..").join("etc").join("passwd");
        let r = read_os_file(&evil, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::TraversalDetected))
        ));
    }

    #[tokio::test]
    async fn strict_confirms_then_fails_closed() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = cfg_for(dir.path());
        // Strict ⇒ OsFileRead is Confirm ⇒ no TTY here ⇒ ConfirmRequired.
        let r = read_os_file(&f, &cfg, AutonomyLevel::Strict, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn emits_read_frame_via_writer() {
        use crate::wal::events::{
            EVENT_TYPE_COMPACTION_MARKER, EVENT_TYPE_EXTENDED, EVENT_TYPE_OS_FILE_READ,
            ExtendedSubtype,
        };
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"audited").unwrap();
        let cfg = cfg_for(dir.path());

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let trust = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(trust.header.event_type, EVENT_TYPE_EXTENDED);
        assert_eq!(
            trust.header.event_subtype,
            ExtendedSubtype::TrustDecision as u8
        );
        let trust_payload: serde_json::Value = serde_json::from_slice(trust.payload).unwrap();
        assert_eq!(trust_payload["subject"], "local");
        assert_eq!(trust_payload["action"], "os_file_read");
        assert_eq!(trust_payload["outcome"], "allowed");

        let marker_offset = SEGMENT_HEADER_LEN + trust.header.total_len as usize;
        let marker = decode_frame(&bytes[marker_offset..])
            .expect("an authenticated TrustDecision must be followed by its marker");
        assert_eq!(marker.header.event_type, EVENT_TYPE_COMPACTION_MARKER);
        let marker_payload: crate::wal::compaction::MarkerPayload =
            serde_json::from_slice(marker.payload).expect("forced marker payload must decode");
        assert_eq!(marker_payload.from_offset, SEGMENT_HEADER_LEN as u64);
        assert_eq!(marker_payload.to_offset, marker_offset as u64);
        assert_eq!(marker_payload.frame_count, 1);
        assert_eq!(marker_payload.hmac_hex.len(), 64);

        let frame = decode_frame(&bytes[marker_offset + marker.header.total_len as usize..])
            .expect("legacy read evidence must follow the forced marker");
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_FILE_READ);
        let v: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(v["bytes"], 7);
    }

    #[tokio::test]
    async fn emits_denied_frame_on_deny_all() {
        use crate::wal::events::EVENT_TYPE_OS_FILE_DENIED;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![],
            max_read_bytes: 1024,
            allowed_write_paths: vec![],
            max_write_bytes: 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let _ = read_os_file(&f, &cfg, AutonomyLevel::Full, AuditSink::Writer(&writer), 0).await;
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_FILE_DENIED);
    }

    // ── app-launch gate (PC-01 app-launch slice) ─────────────────────────────

    /// A real, argument-free, instantly-exiting system binary to allowlist.
    /// `None` on the rare host that lacks it (the dependent test then skips).
    fn real_arg_free_exe() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            for p in ["/bin/true", "/usr/bin/true"] {
                let pb = PathBuf::from(p);
                if pb.is_file() {
                    return Some(pb);
                }
            }
            None
        }
        #[cfg(windows)]
        {
            let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let pb = PathBuf::from(sys).join("System32").join("whoami.exe");
            if pb.is_file() { Some(pb) } else { None }
        }
    }

    fn exec_cfg(exe: &Path) -> OsToolsConfig {
        OsToolsConfig {
            allowed_paths: Vec::new(),
            max_read_bytes: 1024,
            allowed_write_paths: Vec::new(),
            max_write_bytes: 1024,
            allowed_exec_paths: vec![exe.to_path_buf()],
            clipboard: crate::config::ClipboardConfig::default(),
        }
    }

    #[tokio::test]
    async fn launch_deny_all_when_no_exec_allowlist() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // exec allowlist is empty here
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn launch_denied_at_strict() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Strict, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::Denied(_))));
    }

    #[tokio::test]
    async fn launch_confirms_at_standard_no_tty() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Standard, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn launch_confirms_at_elevated_stricter_than_write() {
        // Proves the exec gate is one notch stricter than OsFileWrite (which
        // Elevated ALLOWS): program execution still confirms at Elevated.
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Elevated, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn launch_succeeds_at_full_and_returns_pid() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let (resolved, pid) = launch_os_app(&exe, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
            .await
            .expect("full + allowlisted ⇒ launch");
        assert!(pid > 0);
        assert!(resolved.is_absolute());
    }

    #[tokio::test]
    async fn launch_non_allowlisted_binary_is_denied() {
        // A real, launchable binary that simply isn't the allowlisted one.
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let other = dir.path().join("decoy");
        std::fs::write(&other, b"x").unwrap();
        let cfg = exec_cfg(&exe); // allowlists `exe`, not `other`
        let r = launch_os_app(&other, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::NotInAllowlist(_)))
        ));
    }

    #[tokio::test]
    async fn launch_emits_denied_frame_via_writer() {
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // empty exec allowlist ⇒ deny-all
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let _ = launch_os_app(
            &exe,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            0,
        )
        .await;
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_APP_LAUNCH_DENIED);
    }

    #[tokio::test]
    async fn launch_emits_success_frame_via_writer() {
        use crate::wal::spawn as wal_spawn;

        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        launch_os_app(
            &exe,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .expect("full launch");
        drop(writer);
        join.await.unwrap();

        // GOLD-LF-P1-01 moved the launch audit from "one frame" to an
        // intent/result pair around the spawn, so the success frame is no
        // longer first in the segment — locate it instead of assuming.
        let frames = decode_segment(&seg).await;
        let launch_at = frames
            .iter()
            .position(|(t, _, _)| *t == EVENT_TYPE_OS_APP_LAUNCH)
            .expect("the OS_APP_LAUNCH success frame must exist");
        assert!(frames[launch_at].2["pid"].as_u64().unwrap() > 0);

        let intent_at = frames
            .iter()
            .position(|(t, s, _)| {
                *t == 0x00 && *s == crate::wal::events::ExtendedSubtype::OsAppLaunchIntent as u8
            })
            .expect("a real spawn must be preceded by a durable intent");
        assert!(
            intent_at < launch_at,
            "the intent must be durable before the process starts"
        );
        assert_eq!(
            frames[intent_at].2["intent_id"],
            frames
                .iter()
                .find(|(t, s, _)| {
                    *t == 0x00 && *s == crate::wal::events::ExtendedSubtype::OsAppLaunchResult as u8
                })
                .expect("the intent must be paired by a result")
                .2["intent_id"]
        );
    }

    // ── PC-01 clipboard gate (feature `os-clipboard`) ────────────────────────
    #[cfg(feature = "os-clipboard")]
    mod clipboard_tests {
        use crate::config::ClipboardConfig;
        use crate::os_tools::gate::{
            AuditSink, OsGateError, read_os_clipboard, write_os_clipboard,
        };
        use crate::permissions::AutonomyLevel;
        // `emit_clipboard_access` is private to the gate module — reachable from
        // this descendant via `super::super::`.
        use super::super::emit_clipboard_access;

        fn clip_cfg(enabled: bool, read: bool, write: bool) -> ClipboardConfig {
            ClipboardConfig {
                enabled,
                read_enabled: read,
                write_enabled: write,
                max_clipboard_read_bytes: 4096,
                max_clipboard_write_bytes: 4096,
                allow_newlines_in_write: false,
            }
        }

        #[tokio::test]
        async fn master_switch_off_denies_both_even_at_full() {
            let cfg = clip_cfg(false, true, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_sub_toggle_off_denies() {
            let cfg = clip_cfg(true, false, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn write_sub_toggle_off_denies() {
            let cfg = clip_cfg(true, true, false);
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_denied_at_strict() {
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Strict, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_confirms_fail_closed_at_standard_and_elevated() {
            let cfg = clip_cfg(true, true, true);
            for lvl in [AutonomyLevel::Standard, AutonomyLevel::Elevated] {
                assert!(
                    matches!(
                        read_os_clipboard(&cfg, lvl, AuditSink::None, 0).await,
                        Err(OsGateError::ConfirmRequired(_))
                    ),
                    "read at {lvl:?} must fail closed (no TTY)"
                );
            }
        }

        #[tokio::test]
        async fn write_denied_at_strict_and_standard() {
            let cfg = clip_cfg(true, true, true);
            for lvl in [AutonomyLevel::Strict, AutonomyLevel::Standard] {
                assert!(
                    matches!(
                        write_os_clipboard("x", &cfg, lvl, AuditSink::None, 0).await,
                        Err(OsGateError::Denied(_))
                    ),
                    "write at {lvl:?} must Deny (stricter than app-launch)"
                );
            }
        }

        #[tokio::test]
        async fn write_confirms_fail_closed_at_elevated() {
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Elevated, AuditSink::None, 0).await,
                Err(OsGateError::ConfirmRequired(_))
            ));
        }

        #[tokio::test]
        async fn write_rejects_newline_structurally_even_at_full() {
            // Layer 0b fires BEFORE the autonomy gate + the backend.
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                write_os_clipboard("rm -rf /\n", &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                    .await,
                Err(OsGateError::PastejackingPattern(_))
            ));
            assert!(
                matches!(
                    write_os_clipboard("a\rb", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                    Err(OsGateError::PastejackingPattern(_))
                ),
                "a carriage return is also an auto-execute precondition"
            );
        }

        #[tokio::test]
        async fn write_rejects_unicode_line_terminators() {
            // NEL (U+0085), LS (U+2028), PS (U+2029) — none contain 0x0A/0x0D, so a
            // bytes()-only guard would have missed them. All are auto-execute
            // preconditions and must be refused (allow_newlines off).
            let cfg = clip_cfg(true, true, true);
            for bad in ["a\u{0085}b", "a\u{2028}b", "a\u{2029}b"] {
                assert!(
                    matches!(
                        write_os_clipboard(bad, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                            .await,
                        Err(OsGateError::PastejackingPattern(_))
                    ),
                    "unicode line terminator in {bad:?} must be rejected"
                );
            }
        }

        #[tokio::test]
        async fn write_rejects_control_chars_even_when_newlines_allowed() {
            // ESC (bracketed-paste escape) + NUL + BEL are ALWAYS refused, even
            // with allow_newlines_in_write=true — controls bypass the line-terminator
            // guard and have no legitimate clipboard-text use.
            let mut cfg = clip_cfg(true, true, true);
            cfg.allow_newlines_in_write = true;
            for bad in ["benign\x1b[201~rm -rf /", "a\x00b", "ding\x07"] {
                assert!(
                    matches!(
                        write_os_clipboard(bad, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                            .await,
                        Err(OsGateError::PastejackingPattern(_))
                    ),
                    "control char in {bad:?} must be rejected even with newlines allowed"
                );
            }
        }

        #[tokio::test]
        async fn write_allows_tab_through_the_guard() {
            // Tab is the sole permitted control character — it clears the guard +
            // autonomy and reaches the backend (Ok on a desktop, ClipboardUnavailable
            // on headless CI — both prove the guard did not reject it).
            let cfg = clip_cfg(true, true, true);
            let w = write_os_clipboard("col1\tcol2", &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                .await;
            assert!(
                matches!(w, Ok(_) | Err(OsGateError::ClipboardUnavailable(_))),
                "a tab must pass the control-char guard (got {w:?})"
            );
        }

        #[tokio::test]
        async fn write_too_large_rejected_before_backend() {
            let mut cfg = clip_cfg(true, true, true);
            cfg.max_clipboard_write_bytes = 4;
            assert!(matches!(
                write_os_clipboard(
                    "way too long",
                    &cfg,
                    AutonomyLevel::Full,
                    AuditSink::None,
                    0
                )
                .await,
                Err(OsGateError::WriteTooLarge(_))
            ));
        }

        #[tokio::test]
        async fn newline_opted_in_passes_guard() {
            // With allow_newlines + Full + enabled, the gate clears the pastejack
            // guard + autonomy and reaches the backend. On a desktop the write
            // succeeds; on headless CI the backend is unavailable. BOTH outcomes
            // prove the guard did NOT reject it.
            let mut cfg = clip_cfg(true, true, true);
            cfg.allow_newlines_in_write = true;
            let w = write_os_clipboard(
                "line1\nline2",
                &cfg,
                AutonomyLevel::Full,
                AuditSink::None,
                0,
            )
            .await;
            assert!(
                matches!(w, Ok(_) | Err(OsGateError::ClipboardUnavailable(_))),
                "opted-in multi-line write must pass the pastejack guard (got {w:?})"
            );
        }

        /// The load-bearing no-exfil invariant: NO clipboard frame ever carries
        /// content. Drive a denied write (carrying a secret in the `content` arg)
        /// + a direct access emit through a real WAL writer, then assert no
        /// content-bearing key — and the literal secret — appears in any frame.
        #[tokio::test]
        async fn wal_frame_never_contains_content() {
            use crate::wal::events::{
                EVENT_TYPE_OS_CLIPBOARD_ACCESS, EVENT_TYPE_OS_CLIPBOARD_DENIED,
            };
            use crate::wal::frame::decode_frame;
            use crate::wal::segment_header::SEGMENT_HEADER_LEN;
            use crate::wal::spawn as wal_spawn;

            const SECRET: &str = "SUPER-SECRET-PASSWORD-hunter2";
            let segdir = tempfile::tempdir().unwrap();
            let seg = segdir.path().join("000001.wal");
            let (writer, join) = wal_spawn(seg.clone()).unwrap();
            // (1) Denied write (write_enabled=false) → 0xBD, secret in the arg.
            let _ = write_os_clipboard(
                SECRET,
                &clip_cfg(true, true, false),
                AutonomyLevel::Full,
                AuditSink::Writer(&writer),
                0,
            )
            .await;
            // (2) A FULL write of the secret that clears every gate + reaches the
            //     backend → emits either 0xBC access (byte count) on a desktop or
            //     0xBD "clipboard-backend-unavailable" on headless CI. Either way
            //     the SECRET must NOT appear in the frame.
            let _ = write_os_clipboard(
                SECRET,
                &clip_cfg(true, true, true),
                AutonomyLevel::Full,
                AuditSink::Writer(&writer),
                0,
            )
            .await;
            // (3) A direct success-path access emit (byte count only).
            emit_clipboard_access(AuditSink::Writer(&writer), "read", SECRET.len(), 0).await;
            drop(writer);
            join.await.unwrap();

            let bytes = tokio::fs::read(&seg).await.unwrap();
            let mut cursor = SEGMENT_HEADER_LEN;
            let mut clip_frames = 0;
            while cursor < bytes.len() {
                let Ok(frame) = decode_frame(&bytes[cursor..]) else {
                    break;
                };
                let et = frame.header.event_type;
                if et == EVENT_TYPE_OS_CLIPBOARD_ACCESS || et == EVENT_TYPE_OS_CLIPBOARD_DENIED {
                    let v: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    for forbidden in ["content", "text", "data", "preview", "value", "payload"] {
                        assert!(
                            v.get(forbidden).is_none(),
                            "clipboard frame leaked a content key '{forbidden}': {v}"
                        );
                    }
                    let raw = String::from_utf8_lossy(frame.payload);
                    assert!(
                        !raw.contains(SECRET),
                        "clipboard secret leaked into the WAL frame: {raw}"
                    );
                    clip_frames += 1;
                }
                cursor += frame.header.total_len as usize;
            }
            assert!(
                clip_frames >= 3,
                "expected >=3 clipboard frames, got {clip_frames}"
            );
        }
    }

    // ---- GOLD-LF-P1-01: INTENT/RESULT pre-mutation pairs -------------------

    /// Decode every frame in a finalized segment as
    /// `(event_type, event_subtype, payload_json)`.
    async fn decode_segment(seg: &std::path::Path) -> Vec<(u8, u8, serde_json::Value)> {
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;

        let bytes = tokio::fs::read(seg).await.unwrap();
        let mut out = Vec::new();
        let mut cursor = SEGMENT_HEADER_LEN;
        while cursor < bytes.len() {
            let Ok(frame) = decode_frame(&bytes[cursor..]) else {
                break;
            };
            let json = serde_json::from_slice(frame.payload).unwrap_or(serde_json::Value::Null);
            out.push((frame.header.event_type, frame.header.event_subtype, json));
            cursor += frame.header.total_len as usize;
        }
        out
    }

    #[tokio::test]
    async fn write_records_a_durable_intent_before_the_effect_and_pairs_the_result() {
        use crate::wal::events::ExtendedSubtype;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("audited.txt");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        let frames = decode_segment(&seg).await;
        let intent_at = frames
            .iter()
            .position(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsFileWriteIntent as u8)
            .expect("an OsFileWriteIntent frame must exist");
        let result_at = frames
            .iter()
            .position(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsFileWriteResult as u8)
            .expect("an OsFileWriteResult frame must exist");
        let effect_at = frames
            .iter()
            .position(|(t, _, _)| *t == EVENT_TYPE_OS_FILE_WRITE)
            .expect("the existing OS_FILE_WRITE frame must still be emitted");

        // The whole point of P1-01: the intent is durable BEFORE the effect.
        assert!(
            intent_at < result_at && intent_at < effect_at,
            "intent must precede both its result and the effect frame, got \
             intent={intent_at} result={result_at} effect={effect_at}"
        );
        assert_eq!(
            frames[intent_at].2["intent_id"], frames[result_at].2["intent_id"],
            "result must be paired to its intent by intent_id"
        );
        assert_eq!(frames[result_at].2["outcome"], "written");
        // Contents are hash-bound, never carried verbatim.
        assert_eq!(frames[intent_at].2["bytes"], 7);
        assert!(frames[intent_at].2.get("contents").is_none());
        assert_eq!(
            frames[intent_at].2["contents_sha256"],
            serde_json::Value::String(crate::wal::events::effect_digest(
                b"os-file-write",
                b"payload"
            ))
        );
    }

    #[tokio::test]
    async fn write_is_refused_when_an_authoritative_sink_cannot_record_the_intent() {
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("must-not-exist.txt");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg).unwrap();
        // Kill the writer task so the handle is alive but every append fails.
        join.abort();
        let _ = join.await;

        let err = write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .expect_err("a write whose mandatory intent cannot be recorded must be refused");

        assert!(
            matches!(err, OsGateError::Denied(ref m) if m.contains("pre-write audit intent")),
            "expected a pre-write-intent refusal, got {err:?}"
        );
        // Fail-closed means fail-closed: nothing may reach the disk.
        assert!(
            !target.exists(),
            "the file must not exist when its intent could not be recorded"
        );
    }

    #[tokio::test]
    async fn an_unreachable_audit_forward_still_permits_the_write() {
        // AUDIT-RPC-01 ratified that an unreachable forwarder must not fail the
        // action. P1-01 must not silently revoke that: the hole is reported as
        // `ForwardUnavailable`, not converted into a refusal.
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("forwarded.txt");
        let home = tempdir().unwrap(); // no sidecar ⇒ forward unavailable

        write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::DaemonRpc(home.path()),
            1_700_000_000,
        )
        .await
        .expect("an unreachable audit forward must not fail the write");
        assert!(target.exists());
    }

    #[test]
    fn intent_ids_differ_for_two_effects_on_one_path_in_the_same_second() {
        // Hashing (path, timestamp) alone would collide here — and repeated
        // writes to one path are exactly where a reader must tell the attempts
        // apart.
        let a =
            crate::wal::events::next_intent_id(b"os-file-write", "/tmp/same.txt", 1_700_000_000);
        let b =
            crate::wal::events::next_intent_id(b"os-file-write", "/tmp/same.txt", 1_700_000_000);
        assert_ne!(a, b, "intent ids must be unique per effect, not per second");
    }

    #[tokio::test]
    async fn a_refused_launch_leaves_no_orphan_intent() {
        // An intent means "an effect is about to happen". A launch refused at
        // the allowlist never reaches the spawn, so emitting an intent for it
        // would make every refusal look like an interrupted launch to a
        // forensic reader.
        use crate::wal::events::ExtendedSubtype;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // no allowed_exec_paths ⇒ refused
        let program = dir.path().join("nope.exe");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let outcome = launch_os_app(
            &program,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await;
        drop(writer);
        join.await.unwrap();
        assert!(outcome.is_err(), "an empty exec allowlist must refuse");

        let frames = decode_segment(&seg).await;
        assert!(
            !frames
                .iter()
                .any(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsAppLaunchIntent as u8),
            "a refusal must not emit a pre-mutation intent"
        );
        assert!(
            frames
                .iter()
                .any(|(t, _, _)| *t == EVENT_TYPE_OS_APP_LAUNCH_DENIED),
            "the refusal itself must still be audited"
        );
    }
}
