//! HMAC compaction — Phase 33b SP-2.
//!
//! Periodically the WAL writer emits a `0x15 COMPACTION_MARKER` event
//! carrying an HMAC-SHA256 over every frame written since the previous
//! marker. A downstream reader (or `neoth verify`) recomputes the HMAC
//! from the bytes-on-disk and compares — a tampered tail fails.
//!
//! ## Why HMAC, not plain hash
//!
//! A plain hash is forgeable: an attacker who edits the WAL can also
//! rewrite the trailing marker. HMAC requires a key the attacker
//! doesn't have; the key lives in `~/.neoth/wal/hmac.key` with mode 0600.
//! Compromised filesystem access defeats this — but at that point the
//! adversary already has the operator's secrets. The marker is honest
//! tamper-evidence, not crypto-grade evidence.
//!
//! ## Key lifecycle
//!
//! [`load_or_init_key`] reads `~/.neoth/wal/hmac.key` or generates a fresh
//! 32-byte key on first boot and writes it mode 0600 (Windows: icacls
//! grant-r-owner via the same path as WAL segments — see
//! `wal::win_acl::restrict_to_owner`).
//!
//! ## Cadence
//!
//! [`CompactionState`] tracks bytes-since-marker + frames-since-marker.
//! [`should_emit`] returns true when either threshold is exceeded. The
//! writer calls this after each frame and emits a marker when due.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cap_fs_ext::OpenOptionsFollowExt as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::segment_header::parse_segment_header;

type HmacSha256 = Hmac<Sha256>;

/// Default key path: `~/.neoth/wal/hmac.key`.
pub fn default_key_path() -> PathBuf {
    crate::config::FreedomConfig::default_wal_dir().join("hmac.key")
}

const HMAC_ROTATION_LOCK_NAME: &str = "hmac.key.rotation.lock";
const HMAC_LEASE_RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(25);
const HMAC_LEASE_GIVE_UP_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HmacKeyLeaseMode {
    SharedWriter,
    ExclusiveMutation,
}

/// Stable, capability-bound lifetime fence for the active WAL HMAC identity.
///
/// Normal writers retain a shared lease until their append task exits.
/// Rotation/recovery retains an exclusive lease from its first state read
/// through the durable 0xD9 boundary and key commit. The direct-child binding
/// and no-follow handle prevent a link/reparse leaf from becoming a second lock
/// namespace.
pub(crate) struct HmacKeyLease {
    root: crate::skills::store::BoundDirectory,
    #[cfg(unix)]
    binding: crate::skills::store::BoundChildObject,
    #[cfg(windows)]
    identity_token: String,
    _file: std::fs::File,
    display_path: PathBuf,
}

impl HmacKeyLease {
    pub(crate) fn validate_namespace_binding(&self) -> Result<()> {
        #[cfg(unix)]
        let matches = self.binding.matches_child(
            &self.root.dir,
            OsStr::new(HMAC_ROTATION_LOCK_NAME),
            &self.display_path,
        )?;
        #[cfg(windows)]
        let matches = {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            let mut options = cap_std::fs::OpenOptions::new();
            options
                .read(true)
                .follow(cap_fs_ext::FollowSymlinks::No)
                .access_mode(FILE_GENERIC_READ)
                // The retained pin deliberately denies DELETE sharing. This
                // validation handle requests no DELETE access and therefore
                // coexists without weakening that namespace pin.
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let file = self
                .root
                .dir
                .open_with(OsStr::new(HMAC_ROTATION_LOCK_NAME), &options)
                .with_context(|| {
                    format!(
                        "re-open pinned HMAC-key lease for identity validation {}",
                        self.display_path.display()
                    )
                })?;
            let metadata = file.metadata().with_context(|| {
                format!(
                    "inspect pinned HMAC-key lease during identity validation {}",
                    self.display_path.display()
                )
            })?;
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && cap_file_identity(&metadata) == self.identity_token
        };
        if !matches {
            anyhow::bail!(
                "HMAC-key lease namespace changed while its lock was held: {}",
                self.display_path.display()
            );
        }
        Ok(())
    }
}

fn validate_home_key_path(home: &Path, key_path: &Path) -> Result<PathBuf> {
    let expected = std::path::absolute(home.join("wal").join("hmac.key"))?;
    let requested = std::path::absolute(key_path)?;
    if requested != expected {
        anyhow::bail!(
            "home-bound HMAC key path {} does not match canonical {}",
            key_path.display(),
            expected.display()
        );
    }
    Ok(expected)
}

fn cap_file_identity(metadata: &cap_std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use cap_fs_ext::MetadataExt as _;
        format!("unix:{:016x}:{:016x}:file", metadata.dev(), metadata.ino())
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::MetadataExt as _;
        format!(
            "windows:{:08x}:{:016x}:file",
            metadata.dev(),
            metadata.ino()
        )
    }
}

fn open_bound_hmac_rotation_lock(
    home: &Path,
    key_path: &Path,
    _mode: HmacKeyLeaseMode,
) -> Result<(
    crate::skills::store::BoundDirectory,
    crate::skills::store::BoundChildObject,
    std::fs::File,
    PathBuf,
)> {
    validate_home_key_path(home, key_path)?;
    let wal_path = home.join("wal");
    let trusted_anchor = home.parent().unwrap_or(home);
    let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        &wal_path,
        true,
        "WAL HMAC lease directory",
    )?
    .context("created WAL HMAC lease directory is unavailable")?;
    let name = OsStr::new(HMAC_ROTATION_LOCK_NAME);
    let display = root.display_path.join(name);

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(cap_fs_ext::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
        };
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            // The creation/open handle must coexist with the DELETE-capable
            // identity binder below. A second identity-matched handle removes
            // FILE_SHARE_DELETE before the lease is exposed.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let cap_file = match root.dir.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = cap_std::fs::OpenOptions::new();
            existing
                .read(true)
                .write(true)
                .follow(cap_fs_ext::FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt as _;
                existing.custom_flags(libc::O_NONBLOCK);
            }
            #[cfg(windows)]
            {
                use cap_std::fs::OpenOptionsExt as _;
                use windows_sys::Win32::Storage::FileSystem::{
                    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
                };
                existing
                    .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            root.dir.open_with(name, &existing).with_context(|| {
                format!(
                    "open existing HMAC-key lease without following links {}",
                    display.display()
                )
            })?
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "create capability-bound HMAC-key lease {}",
                    display.display()
                )
            });
        }
    };
    let metadata = cap_file
        .metadata()
        .with_context(|| format!("inspect HMAC-key lease {}", display.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "HMAC-key lease must be a real regular file, not a link or reparse point: {}",
            display.display()
        );
    }
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            cap_file
                .set_permissions(cap_std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("make HMAC-key lease private {}", display.display()))?;
        }
    }
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_file_handle_dacl(&cap_file)
        .with_context(|| format!("protect HMAC-key lease {}", display.display()))?;

    let opened_identity = cap_file_identity(&metadata);
    let (identity_file, binding) =
        crate::skills::store::open_bound_regular_file_readwrite(&root.dir, name, &display)
            .context("bind HMAC-key lease identity")?;
    // `open_bound_regular_file_readwrite` already compares its opened handle
    // with a capability-relative, read-only reopen. Do not call
    // `BoundChildObject::matches_child` here: on Windows that mutation-oriented
    // helper requests DELETE access, which correctly conflicts with an
    // existing shared writer's no-FILE_SHARE_DELETE pin.
    if binding.identity_token() != opened_identity {
        anyhow::bail!(
            "HMAC-key lease changed while its no-follow handle was being bound: {}",
            display.display()
        );
    }
    drop(identity_file);
    #[cfg(windows)]
    let cap_file = {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        let mut pinned = cap_std::fs::OpenOptions::new();
        pinned.read(true).follow(cap_fs_ext::FollowSymlinks::No);
        match _mode {
            HmacKeyLeaseMode::SharedWriter => {
                // Windows shared LockFileEx leases must be carried by a
                // read-only handle; a write-capable handle makes otherwise
                // shared byte-range locks conflict across writers.
                pinned.access_mode(FILE_GENERIC_READ);
            }
            HmacKeyLeaseMode::ExclusiveMutation => {
                pinned
                    .write(true)
                    .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE);
            }
        }
        pinned
            // No FILE_SHARE_DELETE: this handle pins the checked direct child.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let pinned = root
            .dir
            .open_with(name, &pinned)
            .with_context(|| format!("pin HMAC-key lease namespace {}", display.display()))?;
        let pinned_metadata = pinned
            .metadata()
            .with_context(|| format!("inspect pinned HMAC-key lease {}", display.display()))?;
        if !pinned_metadata.is_file()
            || pinned_metadata.file_type().is_symlink()
            || cap_file_identity(&pinned_metadata) != opened_identity
        {
            anyhow::bail!(
                "HMAC-key lease identity changed before its namespace pin: {}",
                display.display()
            );
        }
        drop(cap_file);
        pinned
    };
    Ok((root, binding, cap_file.into_std(), display))
}

pub(crate) fn acquire_hmac_key_lease(
    home: &Path,
    key_path: &Path,
    mode: HmacKeyLeaseMode,
) -> Result<HmacKeyLease> {
    let (root, binding, file, display_path) = open_bound_hmac_rotation_lock(home, key_path, mode)?;
    #[cfg(windows)]
    let identity_token = binding.identity_token().to_owned();
    #[cfg(windows)]
    drop(binding);

    let started = std::time::Instant::now();
    loop {
        let acquired = match mode {
            HmacKeyLeaseMode::SharedWriter => file.try_lock_shared(),
            HmacKeyLeaseMode::ExclusiveMutation => file.try_lock(),
        };
        match acquired {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= HMAC_LEASE_GIVE_UP_AFTER {
                    anyhow::bail!(
                        "HMAC-key {} lease {} remained busy for >5s",
                        match mode {
                            HmacKeyLeaseMode::SharedWriter => "writer",
                            HmacKeyLeaseMode::ExclusiveMutation => "rotation",
                        },
                        display_path.display()
                    );
                }
                std::thread::sleep(HMAC_LEASE_RETRY_EVERY);
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!("acquire HMAC-key {mode:?} lease {}", display_path.display())
                });
            }
        }
    }
    let lease = HmacKeyLease {
        root,
        #[cfg(unix)]
        binding,
        #[cfg(windows)]
        identity_token,
        _file: file,
        display_path,
    };
    lease.validate_namespace_binding()?;
    Ok(lease)
}

/// Emit a marker every 1024 frames OR every 16 MiB. Either threshold
/// gives operators marker coverage within a few minutes of typical use
/// without overwhelming the WAL with metadata events.
pub const MAX_FRAMES_BETWEEN_MARKERS: u32 = 1024;
pub const MAX_BYTES_BETWEEN_MARKERS: u64 = 16 * 1024 * 1024;

/// Running tracker. Writer holds one of these and accumulates frame
/// bytes into the HMAC engine. When [`should_emit`] returns true, the
/// writer calls [`finalise_marker`] to extract the tag + reset.
pub struct CompactionState {
    mac: HmacSha256,
    bytes_since_marker: u64,
    frames_since_marker: u32,
    /// File offset where the current marker window started. Reused as
    /// `from_offset` in the marker payload.
    from_offset: u64,
}

impl CompactionState {
    /// Build a fresh state. `start_offset` is the file offset at which
    /// the first frame in this window will land (usually right after
    /// the segment header on a new segment).
    pub fn new(key: &[u8], start_offset: u64) -> Self {
        let mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        Self {
            mac,
            bytes_since_marker: 0,
            frames_since_marker: 0,
            from_offset: start_offset,
        }
    }

    /// Feed one full frame's bytes (preamble + header + payload + CRC)
    /// into the HMAC engine and update counters.
    pub fn update(&mut self, frame_bytes: &[u8]) {
        self.mac.update(frame_bytes);
        self.bytes_since_marker = self
            .bytes_since_marker
            .saturating_add(frame_bytes.len() as u64);
        self.frames_since_marker = self.frames_since_marker.saturating_add(1);
    }

    pub fn frames(&self) -> u32 {
        self.frames_since_marker
    }
    pub fn bytes(&self) -> u64 {
        self.bytes_since_marker
    }
    pub fn from_offset(&self) -> u64 {
        self.from_offset
    }

    /// Should the writer emit a marker now?
    pub fn should_emit(&self) -> bool {
        self.frames_since_marker >= MAX_FRAMES_BETWEEN_MARKERS
            || self.bytes_since_marker >= MAX_BYTES_BETWEEN_MARKERS
    }

    /// Finalise the current window: extract the HMAC tag (hex-encoded)
    /// and reset the engine for the next window. Caller writes the
    /// marker frame using the returned values + the current file offset
    /// as `to_offset`.
    pub fn finalise_marker(&mut self, key: &[u8], to_offset: u64) -> MarkerPayload {
        // Steal the existing mac to extract the tag; replace with a
        // fresh engine for the next window.
        let mac = std::mem::replace(
            &mut self.mac,
            HmacSha256::new_from_slice(key).expect("HMAC-SHA256 init"),
        );
        let tag = mac.finalize().into_bytes();
        let hmac_hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        let payload = MarkerPayload {
            from_offset: self.from_offset,
            to_offset,
            frame_count: self.frames_since_marker,
            hmac_hex,
            // compaction_epoch is not tracked in CompactionState — it lives in
            // WriterState.compaction_epoch and is injected by the caller into the
            // JSON payload directly (see writer.rs marker emission). Default 0 here.
            compaction_epoch: 0,
        };
        self.from_offset = to_offset;
        self.bytes_since_marker = 0;
        self.frames_since_marker = 0;
        payload
    }
}

/// Payload of an `EVENT_TYPE_COMPACTION_MARKER` event. Serialised to
/// JSON and written as the marker's payload bytes.
///
/// GOLD-PROG-12: `compaction_epoch` is informational — the canonical source
/// of the epoch is the segment header (SegmentHeaderV3). It is included here
/// so forensic tooling (`neoth verify`) can correlate marker events with the
/// segment epoch without re-reading the header. `#[serde(default)]` gives
/// backward compat with existing on-disk JSON markers that lack the field.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MarkerPayload {
    pub from_offset: u64,
    pub to_offset: u64,
    pub frame_count: u32,
    pub hmac_hex: String,
    /// The compaction_epoch from the segment header at the time this marker
    /// was emitted. Informational only — dedup/idempotency uses the header
    /// field, not this JSON field. Defaults to 0 for pre-GOLD-PROG-12 markers.
    #[serde(default)]
    pub compaction_epoch: u32,
}

/// Read the operator's HMAC key from `path`. Generates a fresh 32-byte
/// random key on first call and writes it mode 0600 (unix) / icacls
/// grant:r owner (Windows) + DPAPI-wrapped per-user on Windows when
/// available (K-Sec-4).
///
/// On Windows, when an existing key file lacks the `NEOTH_DPAPIv1`
/// magic header (legacy plaintext from pre-K-Sec-4 installs), the bytes
/// are returned as-is so existing markers verify; the next [`rotate`]
/// or fresh-key path re-writes the file in wrapped form. This keeps
/// upgrades zero-downtime for operators with an existing
/// `~/.neoth/wal/hmac.key`.
pub fn load_or_init_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        return load_existing_key(path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create HMAC key parent {}", parent.display()))?;
    }
    // 32 bytes via the OS CSPRNG. **Fail closed** when the OS RNG is
    // unavailable — a weak HMAC key undermines the whole tamper-evidence
    // story, so we'd rather refuse to write than ship a predictable key.
    // Per Codex audit item #3 (post-SP-2 review).
    let mut key = vec![0u8; 32];
    getrandom::getrandom(&mut key)
        .context("OS RNG unavailable — refusing to generate weak HMAC key")?;

    write_key_securely(path, &key)?;
    Ok(key)
}

/// Load the canonical active HMAC key for `home`, or create it only while the
/// WAL namespace is still provably fresh.
///
/// The caller must hold the instance's HMAC-rotation lock. Keeping the
/// initialization under that same cross-process authority prevents two first
/// starts from minting competing identities. Existing segments, journals,
/// stages, or other WAL artifacts without `hmac.key` are recovery evidence,
/// not permission to invent a replacement key.
pub(crate) fn load_or_initialize_home_key_locked(home: &Path, key_path: &Path) -> Result<Vec<u8>> {
    validate_home_key_path(home, key_path)?;

    match crate::wal::scan::load_home_hmac_keys(home) {
        Ok(keys) => {
            if let Some(active) = keys.into_iter().next() {
                return Ok(active);
            }
        }
        Err(scan_error) => {
            return initialize_home_key_locked(home, key_path).map_err(|init_error| {
                scan_error.context(format!(
                    "active WAL HMAC key was not scanner-readable and safe initialization was \
                     refused: {init_error:#}"
                ))
            });
        }
    }
    initialize_home_key_locked(home, key_path)
}

fn initialize_home_key_locked(home: &Path, key_path: &Path) -> Result<Vec<u8>> {
    let wal_path = home.join("wal");
    let trusted_anchor = home.parent().unwrap_or(home);
    let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        &wal_path,
        true,
        "WAL HMAC key directory",
    )?
    .context("created WAL HMAC key directory is unavailable")?;

    let active_name = std::ffi::OsStr::new("hmac.key");
    let master_name = std::ffi::OsStr::new("master.key");
    let rotation_lock_name = std::ffi::OsStr::new(HMAC_ROTATION_LOCK_NAME);
    let signing_name = std::ffi::OsStr::new("signing.key");
    let signing_lock_name = std::ffi::OsStr::new("signing.key.lock");
    let mut examined_entries = 0usize;
    for entry in root
        .dir
        .entries()
        .with_context(|| format!("enumerate WAL key directory {}", wal_path.display()))?
    {
        examined_entries = examined_entries
            .checked_add(1)
            .context("WAL key initialization entry counter overflow")?;
        if examined_entries > crate::wal::scan::MAX_HOME_KEY_DIRECTORY_ENTRIES {
            anyhow::bail!(
                "WAL key initialization exceeds the {}-entry directory limit under {}",
                crate::wal::scan::MAX_HOME_KEY_DIRECTORY_ENTRIES,
                wal_path.display()
            );
        }
        let name = entry
            .with_context(|| format!("read WAL key entry under {}", wal_path.display()))?
            .file_name();
        match name.as_os_str() {
            name if name == master_name => {
                let display = root.display_path.join(name);
                let body = crate::skills::store::read_regular_file_bounded(
                    &root.dir,
                    name,
                    &display,
                    crate::wal::scan::MAX_HOME_KEY_BYTES,
                )
                .context("validate pre-existing WAL master key before HMAC initialization")?;
                let raw = decode_existing_key(&body, &display)
                    .context("decode pre-existing WAL master key")?;
                crate::wal::crypto::WalMasterKey::from_bytes(&raw)
                    .context("validate pre-existing WAL master key")?;
            }
            name if name == rotation_lock_name || name == signing_lock_name => {
                let display = root.display_path.join(name);
                // Never read the byte range: on Windows the active
                // `LockFileEx` lease intentionally locks it and a read would
                // fail with ERROR_LOCK_VIOLATION. The capability/no-follow
                // handle still proves regular-file identity and metadata.
                let (file, _binding) = crate::skills::store::open_bound_regular_file_readwrite(
                    &root.dir, name, &display,
                )
                .with_context(|| {
                    format!(
                        "validate pre-existing empty WAL key lock {}",
                        display.display()
                    )
                })?;
                let metadata = file.metadata().with_context(|| {
                    format!("inspect pre-existing WAL key lock {}", display.display())
                })?;
                if metadata.len() != 0 {
                    anyhow::bail!(
                        "WAL key lock must be an empty regular file before first HMAC initialization: {}",
                        display.display()
                    );
                }
            }
            name if name == signing_name => {
                let display = root.display_path.join(name);
                let body = crate::skills::store::read_regular_file_bounded(
                    &root.dir,
                    name,
                    &display,
                    crate::wal::scan::MAX_HOME_KEY_BYTES,
                )
                .context("validate pre-existing proof signing key before HMAC initialization")?;
                let raw = maybe_unwrap_dpapi(&body, &display)
                    .context("decode pre-existing proof signing key")?;
                if raw.len() != 32 {
                    anyhow::bail!(
                        "proof signing key must decode to exactly 32 bytes before first HMAC initialization: {}",
                        display.display()
                    );
                }
            }
            _ => {
                anyhow::bail!(
                    "refusing to create a new WAL HMAC identity while `{}` already exists under {}",
                    name.to_string_lossy(),
                    wal_path.display()
                );
            }
        }
    }

    let active_display = root.display_path.join(active_name);
    if std::path::absolute(&active_display)? != std::path::absolute(key_path)? {
        anyhow::bail!(
            "capability-bound WAL HMAC path {} differs from requested {}",
            active_display.display(),
            key_path.display()
        );
    }
    let mut initialized = vec![0u8; 32];
    getrandom::getrandom(&mut initialized)
        .context("OS RNG unavailable; refusing to generate a weak WAL HMAC key")?;
    let encoded = encode_key_for_storage(&active_display, &initialized)
        .context("encode instance-bound WAL HMAC key")?;
    if let Err(create_error) = crate::skills::store::atomic_write_private_child_create_new(
        &root.dir,
        active_name,
        &active_display,
        &encoded,
    ) {
        if let Ok(keys) = crate::wal::scan::load_home_hmac_keys(home)
            && let Some(active) = keys.into_iter().next()
        {
            return Ok(active);
        }
        return Err(create_error).context("create instance-bound WAL HMAC key");
    }

    let stored = crate::skills::store::read_regular_file_bounded(
        &root.dir,
        active_name,
        &active_display,
        crate::wal::scan::MAX_HOME_KEY_BYTES,
    )
    .context("re-open created WAL HMAC key through its bound directory")?;
    let bound_active =
        decode_existing_key(&stored, &active_display).context("decode created WAL HMAC key")?;
    if bound_active != initialized {
        anyhow::bail!(
            "created WAL HMAC key changed between its atomic commit and capability-bound read"
        );
    }

    let scanner_active = crate::wal::scan::load_home_hmac_keys(home)?
        .into_iter()
        .next()
        .context("created WAL HMAC key is not visible to the bounded WAL scanner")?;
    if scanner_active != bound_active {
        anyhow::bail!("WAL emitter and scanner resolved different active HMAC keys");
    }
    Ok(bound_active)
}

fn bound_home_wal_file(home: &Path, path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let wal_path = std::path::absolute(home.join("wal"))?;
    let requested = std::path::absolute(path)?;
    if requested.parent() != Some(wal_path.as_path()) {
        anyhow::bail!(
            "WAL key material must be a direct child of {}: {}",
            wal_path.display(),
            path.display()
        );
    }
    let name = requested
        .file_name()
        .context("WAL key material path has no file name")?;
    let Some(root) = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home.parent().unwrap_or(home),
        &wal_path,
        false,
        "WAL key material directory",
    )?
    else {
        return Ok(None);
    };
    match root.dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect WAL key material {}", requested.display()))
        }
        Ok(_) => {
            crate::skills::store::read_regular_file_bounded(&root.dir, name, &requested, max_bytes)
                .map(Some)
                .with_context(|| format!("read WAL key material {}", requested.display()))
        }
    }
}

pub(crate) fn read_existing_home_wal_file(
    home: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    bound_home_wal_file(home, path, max_bytes)?
        .with_context(|| format!("required WAL key material is missing at {}", path.display()))
}

pub(crate) fn read_optional_home_wal_file(
    home: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    bound_home_wal_file(home, path, max_bytes)
}

pub(crate) fn write_new_home_wal_file(home: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let wal_path = std::path::absolute(home.join("wal"))?;
    let requested = std::path::absolute(path)?;
    if requested.parent() != Some(wal_path.as_path()) {
        anyhow::bail!(
            "new WAL key material must be a direct child of {}: {}",
            wal_path.display(),
            path.display()
        );
    }
    let name = requested
        .file_name()
        .context("new WAL key material path has no file name")?;
    let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home.parent().unwrap_or(home),
        &wal_path,
        true,
        "new WAL key material directory",
    )?
    .context("created WAL key material directory is unavailable")?;
    crate::skills::store::atomic_write_private_child_create_new(&root.dir, name, &requested, bytes)
}

pub(crate) fn write_new_home_key_sibling(home: &Path, path: &Path, key: &[u8]) -> Result<()> {
    let encoded = encode_key_for_storage(path, key)?;
    write_new_home_wal_file(home, path, &encoded)
}

pub(crate) fn replace_home_key(home: &Path, path: &Path, key: &[u8]) -> Result<()> {
    let wal_path = std::path::absolute(home.join("wal"))?;
    let requested = std::path::absolute(path)?;
    if requested.parent() != Some(wal_path.as_path()) {
        anyhow::bail!(
            "replacement WAL key material must be a direct child of {}: {}",
            wal_path.display(),
            path.display()
        );
    }
    let name = requested
        .file_name()
        .context("replacement WAL key material path has no file name")?;
    let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home.parent().unwrap_or(home),
        &wal_path,
        false,
        "replacement WAL key material directory",
    )?
    .context("replacement WAL key material directory is missing")?;
    let encoded = encode_key_for_storage(&requested, key)?;
    crate::skills::store::atomic_write_private_child(&root.dir, name, &requested, &encoded)
}

pub(crate) fn remove_home_wal_file_if_present(home: &Path, path: &Path) -> Result<bool> {
    let wal_path = std::path::absolute(home.join("wal"))?;
    let requested = std::path::absolute(path)?;
    if requested.parent() != Some(wal_path.as_path()) {
        anyhow::bail!(
            "WAL cleanup target must be a direct child of {}: {}",
            wal_path.display(),
            path.display()
        );
    }
    let name = requested
        .file_name()
        .context("WAL cleanup target has no file name")?;
    let Some(root) = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home.parent().unwrap_or(home),
        &wal_path,
        false,
        "WAL cleanup directory",
    )?
    else {
        return Ok(false);
    };
    let removed = crate::skills::store::remove_child_file_if_present(&root.dir, name, &requested)?;
    if removed {
        crate::skills::store::sync_parent_directory(&root.dir, &root.display_path)
            .context("durably commit WAL cleanup")?;
    }
    Ok(removed)
}

pub(crate) fn load_existing_home_key(home: &Path, key_path: &Path) -> Result<Vec<u8>> {
    validate_home_key_path(home, key_path)?;
    let body = read_existing_home_wal_file(home, key_path, crate::wal::scan::MAX_HOME_KEY_BYTES)?;
    decode_existing_key(&body, key_path)
}

pub(crate) fn load_existing_home_key_sibling(home: &Path, path: &Path) -> Result<Vec<u8>> {
    let body = read_existing_home_wal_file(home, path, crate::wal::scan::MAX_HOME_KEY_BYTES)?;
    decode_existing_key(&body, path)
}

/// Load an already-created WAL HMAC key without silently generating a new
/// identity. Proof readers use this fail-closed path: an absent key means the
/// existing WAL cannot be authenticated and must not be treated as empty.
pub(crate) fn load_existing_key(path: &Path) -> Result<Vec<u8>> {
    let body = std::fs::read(path)
        .with_context(|| format!("read existing HMAC key {}", path.display()))?;
    decode_existing_key(&body, path)
}

/// Decode key bytes read through a capability-bound no-follow handle.
///
/// Keeping the storage decoding separate lets security-sensitive scanners
/// avoid reopening `hmac.key` through an ambient path after they already bound
/// `<home>/wal`.
pub(crate) fn decode_existing_key(body: &[u8], display_path: &Path) -> Result<Vec<u8>> {
    let key_bytes = maybe_unwrap_dpapi(body, display_path)?;
    if key_bytes.len() < 16 {
        anyhow::bail!(
            "HMAC key at {} is shorter than 16 bytes; refuse to use weak key",
            display_path.display()
        );
    }
    Ok(key_bytes)
}

/// SC-09 Tier-1 recovery: re-wrap an operator-supplied RAW HMAC key for
/// THIS machine/user and install it at `path`, OVERWRITING any existing
/// key file (the typical case: a key DPAPI-bound to a different Windows
/// user/box after a restore, which `load_or_init_key` can no longer
/// unwrap). The raw bytes come from a `neoth security backup-hmac-key`
/// backup taken on the original host. On Windows the bytes are
/// DPAPI-wrapped for the current user before writing (re-binding the
/// restored key to this machine); on unix the file is written mode 0600.
/// Refuses keys shorter than 16 bytes — the same weak-key floor as
/// [`load_or_init_key`].
///
/// Replacement is an fsync + atomic sibling rename: readers observe either
/// the complete old key or the complete replacement, never an absent/torn key.
pub fn rewrap_key(path: &Path, raw_key: &[u8]) -> Result<()> {
    if raw_key.len() < 16 {
        anyhow::bail!(
            "refusing to install HMAC key shorter than 16 bytes ({} given) — \
             a weak key undermines WAL tamper-evidence",
            raw_key.len()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create HMAC key parent {}", parent.display()))?;
    }
    let encoded = encode_key_for_storage(path, raw_key)?;
    crate::util::atomic_write::atomic_write_private(path, &encoded)
        .with_context(|| format!("atomically replace HMAC key at {}", path.display()))?;
    Ok(())
}

/// On Windows: if the file is DPAPI-wrapped, unwrap. Otherwise return
/// the bytes unchanged (legacy plaintext path). Linux: always return
/// unchanged.
#[cfg(windows)]
pub(crate) fn maybe_unwrap_dpapi(body: &[u8], path: &Path) -> Result<Vec<u8>> {
    if crate::wal::dpapi::is_wrapped(body) {
        crate::wal::dpapi::unprotect(body)
            .with_context(|| format!("DPAPI-unwrap HMAC key at {}", path.display()))
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(not(windows))]
pub(crate) fn maybe_unwrap_dpapi(body: &[u8], _path: &Path) -> Result<Vec<u8>> {
    Ok(body.to_vec())
}

#[cfg(unix)]
pub(crate) fn write_key_securely(path: &Path, key: &[u8]) -> Result<()> {
    crate::util::atomic_write::write_private_create_new_durable(path, key).with_context(|| {
        format!(
            "durably create HMAC key at {} with mode 0600",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn encode_key_for_storage(_path: &Path, key: &[u8]) -> Result<Vec<u8>> {
    Ok(key.to_vec())
}

#[cfg(windows)]
pub(crate) fn encode_key_for_storage(path: &Path, key: &[u8]) -> Result<Vec<u8>> {
    match crate::wal::dpapi::protect(key) {
        Ok(wrapped) => Ok(wrapped),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "DPAPI wrap unavailable; writing HMAC key plaintext with DACL fallback"
            );
            Ok(key.to_vec())
        }
    }
}

#[cfg(windows)]
pub(crate) fn write_key_securely(path: &Path, key: &[u8]) -> Result<()> {
    // K-Sec-4: DPAPI-wrap before writing so a copy of the file is
    // useless outside the current Windows user account. If DPAPI is
    // unavailable (no user session, SYSTEM context, …) log a warning
    // and fall back to plaintext + DACL — the file stays as protected
    // as it was pre-K-Sec-4 instead of failing key generation.
    let payload = encode_key_for_storage(path, key)?;
    crate::util::atomic_write::write_private_create_new_durable(path, &payload)
        .with_context(|| format!("durably create private HMAC key at {}", path.display()))?;
    Ok(())
}

/// Verify a marker against the bytes between `from_offset` and `to_offset`
/// in `segment_path`. Returns `Ok(())` on match, `Err` with a clear
/// message on mismatch.
pub fn verify_marker(segment_path: &Path, key: &[u8], marker: &MarkerPayload) -> Result<()> {
    let raw = std::fs::read(segment_path)
        .with_context(|| format!("read segment {}", segment_path.display()))?;
    // Compaction markers are computed over the UNCOMPRESSED frame stream at
    // logical offsets. A finalized compressed segment (v2 header + zstd blob)
    // stores those frames compressed, so the marker offsets no longer point at
    // raw file bytes — reconstruct the logical (decompressed) bytes first, else
    // `verify` would silently mis-read (false FAIL) or skip (false clean) every
    // compressed segment, defeating the whole tamper-evidence guarantee.
    let (_, logical) = logical_segment_bytes(&raw)
        .with_context(|| format!("reconstruct logical bytes for {}", segment_path.display()))?;
    verify_marker_bytes(&logical, key, marker).map_err(|e| {
        // Preserve the segment-path context the operator needs.
        anyhow::anyhow!("{} in {}", e, segment_path.display())
    })
}

/// Reconstruct a segment's LOGICAL byte layout — the bytes the compaction
/// markers' `from_offset`/`to_offset` index into. For an uncompressed (v1)
/// segment that is just the raw file (borrowed, no copy). For a compressed (v2)
/// segment it is `header || decompress(frame-blob)` — because the marker offsets
/// were computed over the uncompressed frame stream during live operation, and
/// the v2 header length (61) is identical live + finalized (the live segment is
/// already v2 when compression is on), so no offset shift is needed. Returns the
/// header length too, so frame walkers know where the first frame starts.
pub(crate) fn logical_segment_bytes(raw: &[u8]) -> Result<(usize, Cow<'_, [u8]>)> {
    // CRYPTO-04d — only consult the default-home segment key when the body is
    // actually AEAD-framed; the common plaintext path never touches the key
    // store. This makes EVERY reader (verify / scan / indexer / proof_bundle)
    // decrypt sealed segments transparently, with zero signature ripple.
    if segment_body_is_encrypted(raw) {
        return logical_segment_bytes_with_key(raw, crate::wal::master_key::default_segment_key());
    }
    logical_segment_bytes_with_key(raw, None)
}

/// Reconstruct a segment using the master key owned by an explicit daemon
/// instance. The daemon indexer uses this for custom homes so encrypted WAL
/// segments are never opened with the process-default key.
pub(crate) fn logical_segment_bytes_at_home<'a>(
    raw: &'a [u8],
    home: &Path,
) -> Result<(usize, Cow<'a, [u8]>)> {
    logical_segment_bytes_at_home_capped(raw, home, crate::wal::compress::MAX_DECOMPRESSED_BYTES)
}

/// Home-bound reconstruction with a caller-selected logical-frame ceiling.
///
/// Security-sensitive scanners use a substantially smaller cap than the
/// general forensic reader and must never fall back to the process-global
/// segment key for a custom instance home.
pub(crate) fn logical_segment_bytes_at_home_capped<'a>(
    raw: &'a [u8],
    home: &Path,
    max_frame_bytes: u64,
) -> Result<(usize, Cow<'a, [u8]>)> {
    if segment_body_is_encrypted(raw) {
        let key = crate::wal::master_key::segment_key_at(home);
        return logical_segment_bytes_with_key_capped(raw, key.as_ref(), max_frame_bytes);
    }
    logical_segment_bytes_with_key_capped(raw, None, max_frame_bytes)
}

/// True when a parsed segment's body begins with the AEAD frame magic.
fn segment_body_is_encrypted(raw: &[u8]) -> bool {
    let Ok(hdr) = parse_segment_header(raw) else {
        return false;
    };
    let body = raw.get(hdr.header_len()..).unwrap_or(&[]);
    crate::wal::crypto::is_encrypted(body)
}

/// GOLD-ADAPT-CRYPTO-04c — like [`logical_segment_bytes`] but decrypts an
/// encrypt-on-seal (CRYPTO-04d) segment body with `key` BEFORE the existing
/// decompress path. The on-disk layout of an encrypted sealed segment is
/// `[plaintext header (AAD)] [ENC_MAGIC ‖ nonce ‖ ciphertext]`, where the
/// ciphertext is `encrypt(compress(frames))` (or `encrypt(frames)` when
/// compression is off). The plaintext header is the AEAD AAD, so a tampered
/// header fails the tag.
///
/// `key = None` is the legacy path: a non-encrypted segment reconstructs
/// EXACTLY as before (borrow, no copy); an encrypted one returns `Err` (you
/// need the key to read it). Every existing caller passes `None`, so until
/// encrypt-on-seal lands this is a no-op — `is_encrypted(body)` is never true.
pub(crate) fn logical_segment_bytes_with_key<'a>(
    raw: &'a [u8],
    key: Option<&crate::wal::crypto::WalSegmentKey>,
) -> Result<(usize, Cow<'a, [u8]>)> {
    logical_segment_bytes_with_key_capped(raw, key, crate::wal::compress::MAX_DECOMPRESSED_BYTES)
}

pub(crate) fn logical_segment_bytes_with_key_capped<'a>(
    raw: &'a [u8],
    key: Option<&crate::wal::crypto::WalSegmentKey>,
    max_frame_bytes: u64,
) -> Result<(usize, Cow<'a, [u8]>)> {
    use crate::wal::crypto;
    // A file without a parseable segment header — a bare frame stream (minimal
    // test fixture) or a pre-header artifact — is treated as raw, frames starting
    // at offset 0.
    let Ok(hdr) = parse_segment_header(raw) else {
        return Ok((0, Cow::Borrowed(raw)));
    };
    let header_len = hdr.header_len();
    let body = raw.get(header_len..).unwrap_or(&[]);

    // ── CRYPTO-04c decrypt layer ── peel the AEAD frame off the body first.
    // No-op on legacy plaintext segments (is_encrypted == false).
    let frame_blob: Cow<'a, [u8]> = if crypto::is_encrypted(body) {
        let k = key.ok_or_else(|| {
            anyhow::anyhow!("WAL segment body is encrypted but no segment key was provided")
        })?;
        let (nonce, ct) = crypto::split_encrypted(body)?;
        let plain = crypto::decrypt_blob(k, &nonce, &raw[..header_len], ct)
            .context("decrypt sealed WAL segment")?;
        if plain.len() as u64 > max_frame_bytes {
            anyhow::bail!(
                "decrypted WAL frame body is {} bytes, exceeding the {}-byte scanner cap",
                plain.len(),
                max_frame_bytes
            );
        }
        Cow::Owned(plain)
    } else {
        if body.len() as u64 > max_frame_bytes {
            anyhow::bail!(
                "WAL frame body is {} bytes, exceeding the {}-byte scanner cap",
                body.len(),
                max_frame_bytes
            );
        }
        Cow::Borrowed(body)
    };

    // Only a header that sets the compression flag triggers decompression; a
    // flagged-compressed blob that won't inflate IS an error (tamper-suspect).
    if !hdr.is_compressed() {
        return match frame_blob {
            // Not encrypted + not compressed → the raw file is already logical.
            Cow::Borrowed(_) => Ok((header_len, Cow::Borrowed(raw))),
            // Encryption-only → stitch the plaintext header onto the decrypted frames.
            Cow::Owned(plain) => {
                let mut logical = Vec::with_capacity(header_len + plain.len());
                logical.extend_from_slice(&raw[..header_len]);
                logical.extend_from_slice(&plain);
                Ok((header_len, Cow::Owned(logical)))
            }
        };
    }
    let frames = crate::wal::compress::decompress_frames_capped(&frame_blob, max_frame_bytes)
        .context("decompress segment frame blob")?;
    let mut logical = Vec::with_capacity(header_len + frames.len());
    logical.extend_from_slice(&raw[..header_len]);
    logical.extend_from_slice(&frames);
    Ok((header_len, Cow::Owned(logical)))
}

/// Verify a marker's HMAC against an in-memory LOGICAL segment byte slice (see
/// [`logical_segment_bytes`]). Separated from [`verify_marker`] so the verifier
/// can decompress a compressed segment ONCE and check every marker against the
/// shared reconstruction instead of re-reading + re-decompressing per marker.
pub fn verify_marker_bytes(segment_bytes: &[u8], key: &[u8], marker: &MarkerPayload) -> Result<()> {
    let from = marker.from_offset as usize;
    let to = marker.to_offset as usize;
    if to <= from {
        anyhow::bail!("marker covers zero bytes — refuse to verify empty window");
    }
    let buf = segment_bytes.get(from..to).with_context(|| {
        format!(
            "marker window {from}..{to} out of bounds for a {}-byte logical segment",
            segment_bytes.len()
        )
    })?;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(buf);
    let tag = mac.finalize().into_bytes();
    let computed_hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    if computed_hex != marker.hmac_hex {
        anyhow::bail!(
            "HMAC mismatch ({}..{}): marker={}, computed={}. \
             WAL window may have been tampered with.",
            marker.from_offset,
            marker.to_offset,
            marker.hmac_hex,
            computed_hex,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto04c_decrypts_encrypted_segment_at_chokepoint() {
        use crate::wal::compress::compress_frames;
        use crate::wal::crypto::{self, INFO_WAL_SEGMENT, WalMasterKey, derive_subkey};
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
        };

        let key = derive_subkey(
            &WalMasterKey::from_bytes(&[3u8; 32]).unwrap(),
            INFO_WAL_SEGMENT,
        )
        .unwrap();
        let frames = b"the raw frame stream the writer held before sealing".repeat(4);

        // Build: header(plaintext AAD) || ENC_MAGIC ‖ nonce ‖ encrypt(maybe-compress(frames)).
        let build = |compressed: bool| -> Vec<u8> {
            let flag = if compressed {
                SEGMENT_FLAG_COMPRESSED
            } else {
                0
            };
            let header = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], flag)
                .to_le_bytes()
                .to_vec();
            let blob = if compressed {
                compress_frames(&frames).unwrap()
            } else {
                frames.clone()
            };
            let nonce = [7u8; 12];
            let ct = crypto::encrypt_blob(&key, &nonce, &header, &blob).unwrap();
            let mut seg = header.clone();
            seg.extend_from_slice(&crypto::frame_encrypted(&nonce, &ct));
            seg
        };

        for compressed in [false, true] {
            let seg = build(compressed);
            // With the key: decrypts (+ decompresses) back to header || frames.
            let (hl, logical) = logical_segment_bytes_with_key(&seg, Some(&key)).unwrap();
            assert_eq!(hl, SEGMENT_HEADER_V2_LEN);
            assert_eq!(
                &logical[hl..],
                &frames[..],
                "compressed={compressed}: round-trips to the frame stream"
            );
            // Without the key an encrypted segment cannot be read (default path too).
            assert!(logical_segment_bytes_with_key(&seg, None).is_err());
            assert!(logical_segment_bytes(&seg).is_err());
            // Wrong key → AEAD tag fails closed.
            let wrong = derive_subkey(
                &WalMasterKey::from_bytes(&[9u8; 32]).unwrap(),
                INFO_WAL_SEGMENT,
            )
            .unwrap();
            assert!(logical_segment_bytes_with_key(&seg, Some(&wrong)).is_err());
        }

        // A legacy plaintext segment is unaffected by passing a key (passthrough).
        let header = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], 0)
            .to_le_bytes()
            .to_vec();
        let mut plain = header.clone();
        plain.extend_from_slice(&frames);
        let (hl, logical) = logical_segment_bytes_with_key(&plain, Some(&key)).unwrap();
        assert_eq!(&logical[hl..], &frames[..]);
    }
    use tempfile::tempdir;

    #[test]
    fn should_emit_after_frame_threshold() {
        let mut state = CompactionState::new(b"k", 0);
        for _ in 0..MAX_FRAMES_BETWEEN_MARKERS - 1 {
            state.update(&[0u8; 1]);
            assert!(!state.should_emit());
        }
        state.update(&[0u8; 1]);
        assert!(state.should_emit(), "expected emit after frame threshold");
    }

    #[test]
    fn should_emit_after_byte_threshold() {
        let mut state = CompactionState::new(b"k", 0);
        let big = vec![0u8; (MAX_BYTES_BETWEEN_MARKERS + 1) as usize];
        state.update(&big);
        assert!(state.should_emit());
    }

    #[test]
    fn finalise_resets_window() {
        let key = b"secret";
        let mut state = CompactionState::new(key, 100);
        state.update(b"first frame");
        state.update(b"second frame");
        let marker = state.finalise_marker(key, 250);
        assert_eq!(marker.from_offset, 100);
        assert_eq!(marker.to_offset, 250);
        assert_eq!(marker.frame_count, 2);
        assert_eq!(marker.hmac_hex.len(), 64);

        // After finalise, state is reset.
        assert_eq!(state.frames(), 0);
        assert_eq!(state.bytes(), 0);
        assert_eq!(state.from_offset(), 250);
    }

    #[test]
    fn finalise_produces_deterministic_tag_for_same_input() {
        let key = b"shared-key";
        let mut a = CompactionState::new(key, 0);
        a.update(b"alpha");
        let m_a = a.finalise_marker(key, 5);

        let mut b = CompactionState::new(key, 0);
        b.update(b"alpha");
        let m_b = b.finalise_marker(key, 5);

        assert_eq!(m_a.hmac_hex, m_b.hmac_hex);
    }

    #[test]
    fn different_keys_produce_different_tags() {
        let mut a = CompactionState::new(b"k1", 0);
        a.update(b"x");
        let mut b = CompactionState::new(b"k2", 0);
        b.update(b"x");
        assert_ne!(
            a.finalise_marker(b"k1", 1).hmac_hex,
            b.finalise_marker(b"k2", 1).hmac_hex,
        );
    }

    #[test]
    fn load_or_init_key_generates_on_first_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        assert!(!path.exists());
        let sync_attempts_before =
            crate::util::atomic_write::create_new_parent_sync_attempts_for_test();
        let key = load_or_init_key(&path).unwrap();
        assert_eq!(key.len(), 32);
        assert!(path.exists());
        assert!(
            crate::util::atomic_write::create_new_parent_sync_attempts_for_test()
                > sync_attempts_before,
            "fresh HMAC-key creation must durably commit its directory entry"
        );
        // Second call returns the same key.
        let key2 = load_or_init_key(&path).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn load_or_init_rejects_too_short_existing_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        std::fs::write(&path, b"short").unwrap();
        let r = load_or_init_key(&path);
        assert!(r.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn load_or_init_passes_through_legacy_plaintext_key() {
        // Backward-compat: an existing pre-K-Sec-4 install holds a 32-
        // byte plaintext key. `load_or_init_key` must return those
        // bytes verbatim so existing markers continue to verify.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let legacy = vec![0x42u8; 32];
        std::fs::write(&path, &legacy).unwrap();

        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(
            loaded, legacy,
            "legacy plaintext key must roundtrip unchanged"
        );
    }

    #[cfg(windows)]
    #[test]
    fn fresh_key_is_dpapi_wrapped_on_disk() {
        // K-Sec-4 contract: a freshly-generated key is wrapped on disk.
        // We can't compare the wrapped bytes to anything (DPAPI is
        // non-deterministic) — pin (a) the on-disk bytes carry the
        // NEOTH_DPAPIv1 magic OR (b) DPAPI was unavailable and we
        // fell back to plaintext. Either is a tested branch.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let key = load_or_init_key(&path).unwrap();
        assert_eq!(key.len(), 32);

        let on_disk = std::fs::read(&path).unwrap();
        crate::wal::win_native::verify_private_dacl(&path).unwrap();
        let wrapped = crate::wal::dpapi::is_wrapped(&on_disk);
        let plaintext_fallback = on_disk == key;
        assert!(
            wrapped || plaintext_fallback,
            "on-disk key must be either DPAPI-wrapped or the plaintext fallback"
        );

        // Second call must return the same logical key regardless of
        // whether DPAPI was used.
        let key2 = load_or_init_key(&path).unwrap();
        assert_eq!(key, key2);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        load_or_init_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rewrap_key_refuses_short_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let err = rewrap_key(&path, b"short").unwrap_err();
        assert!(
            err.to_string().contains("shorter than 16 bytes"),
            "got: {err}"
        );
        assert!(
            !path.exists(),
            "no key file written when the key is rejected"
        );
    }

    #[test]
    fn rewrap_key_roundtrips_via_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let raw = vec![7u8; 32];
        rewrap_key(&path, &raw).unwrap();
        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(
            loaded, raw,
            "rewrapped key must load back to the same bytes"
        );
    }

    #[test]
    fn rewrap_key_overwrites_existing_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        rewrap_key(&path, &[1u8; 32]).unwrap();
        let restored = vec![9u8; 24];
        rewrap_key(&path, &restored).unwrap();
        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(loaded, restored, "rewrap must overwrite the prior key");
    }

    #[test]
    fn verify_marker_succeeds_on_matching_bytes() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        let key = b"k";
        let frames: &[&[u8]] = &[b"first", b"second", b"third"];

        // Lay down some bytes on disk to emulate frames.
        let mut bytes = Vec::new();
        for f in frames {
            bytes.extend_from_slice(f);
        }
        std::fs::write(&seg_path, &bytes).unwrap();

        // Compute the marker the writer would have emitted.
        let mut state = CompactionState::new(key, 0);
        for f in frames {
            state.update(f);
        }
        let marker = state.finalise_marker(key, bytes.len() as u64);
        verify_marker(&seg_path, key, &marker).expect("matching window verifies");
    }

    #[test]
    fn verify_marker_detects_tamper() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        let key = b"k";
        let original = b"alpha-beta-gamma".to_vec();
        std::fs::write(&seg_path, &original).unwrap();

        let mut state = CompactionState::new(key, 0);
        state.update(&original);
        let marker = state.finalise_marker(key, original.len() as u64);

        // Tamper: flip one byte.
        let mut tampered = original.clone();
        tampered[5] ^= 0x01;
        std::fs::write(&seg_path, &tampered).unwrap();

        let r = verify_marker(&seg_path, key, &marker);
        assert!(r.is_err(), "tampered bytes must fail HMAC check");
        let msg = format!("{r:?}");
        assert!(msg.contains("HMAC mismatch"), "error must explain: {msg}");
    }

    #[test]
    fn verify_marker_works_on_compressed_segment() {
        // The gap this closes: a finalized COMPRESSED (v2 header + zstd blob)
        // segment stores its frames + compaction markers inside the blob, at
        // logical offsets. The old `verify_marker` seeked RAW file bytes → it
        // silently mis-read every compressed segment. `verify_marker` now
        // reconstructs the logical bytes first, so the HMAC check actually runs.
        use crate::wal::HeaderBuilder;
        use crate::wal::compress::compress_frames;
        use crate::wal::events::{EVENT_TYPE_COMPACTION_MARKER, EVENT_TYPE_RAW_TEXT};
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
        };

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let key = b"compression-verify-test-key";
        let from = SEGMENT_HEADER_V2_LEN as u64; // 61 — live segment is already v2 when compressed

        // Build the raw frame stream the writer would hold before compressing:
        // 3 data frames + a COMPACTION_MARKER over them. `tamper` flips a byte in
        // frame 1's payload AND fixes that frame's CRC (so the frame still decodes
        // and the marker after it stays findable) — the marker's pre-tamper HMAC
        // then mismatches, exactly like a post-redaction segment.
        let build_raw = |tamper: bool| -> (Vec<u8>, MarkerPayload) {
            let mut data = Vec::new();
            for p in [b"alpha".as_slice(), b"bravo", b"charlie"] {
                let h = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, p).build();
                data.extend_from_slice(&encode_frame(&h, p));
            }
            let to = from + data.len() as u64;
            let mut state = CompactionState::new(key, from);
            state.update(&data);
            let marker = state.finalise_marker(key, to);
            if tamper {
                let flen = encode_frame(
                    &HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, b"alpha".as_slice()).build(),
                    b"alpha",
                )
                .len();
                data[100] ^= 0x01; // 4 magic + 96 header = first payload byte
                let crc_off = flen - 4;
                let new_crc = crc32c::crc32c(&data[..crc_off]);
                data[crc_off..crc_off + 4].copy_from_slice(&new_crc.to_le_bytes());
            }
            // Append the marker FRAME so it lands inside the compressed blob.
            let mpayload = serde_json::to_vec(&marker).unwrap();
            let mh = HeaderBuilder::new(EVENT_TYPE_COMPACTION_MARKER, &mpayload).build();
            data.extend_from_slice(&encode_frame(&mh, &mpayload));
            (data, marker)
        };
        let write_compressed = |raw: &[u8]| {
            let blob = compress_frames(raw).unwrap();
            let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
            let mut file = hdr.to_le_bytes().to_vec();
            file.extend_from_slice(&blob);
            std::fs::write(&seg, file).unwrap();
        };

        // CLEAN — the compressed segment verifies.
        let (raw_clean, marker) = build_raw(false);
        write_compressed(&raw_clean);
        // logical reconstruction = header + decompressed frames.
        let file = std::fs::read(&seg).unwrap();
        let (hl, logical) = logical_segment_bytes(&file).unwrap();
        assert_eq!(hl, SEGMENT_HEADER_V2_LEN);
        assert_eq!(
            &logical[hl..],
            &raw_clean[..],
            "decompress restores the frame stream"
        );
        verify_marker(&seg, key, &marker).expect("compressed segment verifies clean");

        // TAMPER — a changed byte inside the compressed window now FAILS (no more
        // silent false-clean on compressed segments).
        let (raw_tampered, _) = build_raw(true);
        write_compressed(&raw_tampered);
        let r = verify_marker(&seg, key, &marker);
        assert!(
            r.is_err(),
            "tampered compressed window must fail HMAC: {r:?}"
        );
        assert!(format!("{r:?}").contains("HMAC mismatch"), "got: {r:?}");
    }

    #[test]
    fn verify_marker_rejects_zero_byte_window() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        std::fs::write(&seg_path, b"").unwrap();
        let marker = MarkerPayload {
            from_offset: 0,
            to_offset: 0,
            frame_count: 0,
            hmac_hex: "deadbeef".into(),
            compaction_epoch: 0,
        };
        let r = verify_marker(&seg_path, b"k", &marker);
        assert!(r.is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn hmac_rotation_lock_refuses_a_symlink_or_reparse_leaf() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let outside = home.path().join("outside-lock");
        std::fs::write(&outside, b"sentinel").unwrap();
        let lock = wal.join(HMAC_ROTATION_LOCK_NAME);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &lock).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_file(&outside, &lock) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create test reparse leaf: {error}");
        }

        let error = acquire_hmac_key_lease(
            home.path(),
            &wal.join("hmac.key"),
            HmacKeyLeaseMode::ExclusiveMutation,
        )
        .err()
        .expect("link/reparse lock leaves must never define the lease namespace");
        assert!(
            format!("{error:#}").contains("without following links")
                || format!("{error:#}").contains("real regular file"),
            "unexpected no-follow lock error: {error:#}"
        );
        assert_eq!(std::fs::read(outside).unwrap(), b"sentinel");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn first_hmac_initialization_refuses_a_symlink_or_reparse_key_leaf() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let outside = home.path().join("outside-key");
        std::fs::write(&outside, [0x55; 32]).unwrap();
        let key_path = wal.join("hmac.key");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &key_path).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_file(&outside, &key_path) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create test key reparse leaf: {error}");
        }

        let lease =
            acquire_hmac_key_lease(home.path(), &key_path, HmacKeyLeaseMode::ExclusiveMutation)
                .unwrap();
        let error = load_or_initialize_home_key_locked(home.path(), &key_path)
            .expect_err("first initialization must not replace a linked key leaf");
        assert!(
            format!("{error:#}").contains("refusing to create a new WAL HMAC identity")
                || format!("{error:#}").contains("real regular file"),
            "unexpected linked-key error: {error:#}"
        );
        lease.validate_namespace_binding().unwrap();
        assert_eq!(std::fs::read(outside).unwrap(), [0x55; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn writer_and_rotation_leases_detect_unlinked_lock_replacement() {
        for mode in [
            HmacKeyLeaseMode::SharedWriter,
            HmacKeyLeaseMode::ExclusiveMutation,
        ] {
            let home = tempdir().unwrap();
            let wal = home.path().join("wal");
            let key_path = wal.join("hmac.key");
            let lease = acquire_hmac_key_lease(home.path(), &key_path, mode).unwrap();
            let lock_path = wal.join(HMAC_ROTATION_LOCK_NAME);

            std::fs::remove_file(&lock_path).unwrap();
            std::fs::write(&lock_path, b"replacement-inode").unwrap();

            let error = lease
                .validate_namespace_binding()
                .expect_err("a replacement inode must invalidate the held lease");
            assert!(
                format!("{error:#}").contains("namespace changed"),
                "unexpected replacement error for {mode:?}: {error:#}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn fresh_init_validates_an_actively_locked_rotation_file_by_metadata() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        let key_path = wal.join("hmac.key");
        let lease =
            acquire_hmac_key_lease(home.path(), &key_path, HmacKeyLeaseMode::ExclusiveMutation)
                .unwrap();

        let key = load_or_initialize_home_key_locked(home.path(), &key_path)
            .expect("fresh init must not read the LockFileEx-locked byte range");
        assert_eq!(key.len(), 32);
        assert!(key_path.is_file());
        lease.validate_namespace_binding().unwrap();
    }
}
