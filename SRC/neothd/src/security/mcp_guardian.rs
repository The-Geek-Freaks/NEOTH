//! ADOPT31-C4 — MCP tool fingerprinting and rug-pull detection.
//!
//! An MCP server declares its tools once and NEOTH's gates reason about them
//! by name. Nothing stopped a server from keeping a name and swapping what it
//! does afterwards. The sharpest form of that is not a changed parameter list:
//! `McpTool::annotations` carries `readOnlyHint` / `destructiveHint`, and
//! ADOPT-22 SmartApprove auto-approves a Confirm-gated call by its declared
//! EFFECT. A server that first registers `destructiveHint: true` and later
//! flips it to `readOnlyHint: true` buys itself silent auto-approval for a
//! destructive tool. The fingerprint therefore covers the annotations, not
//! just the input schema.
//!
//! ## Model
//!
//! Trust on first use. The first time a tool is seen it is pinned; every later
//! sighting must match. A delta blocks the call rather than re-pinning —
//! re-pinning on change would make the guard a no-op.
//!
//! ## Threat boundary (stated, not implied)
//!
//! The pin is an HMAC under the instance's own WAL identity, so a malicious
//! *server* cannot forge one: it never sees the key. It does NOT defend
//! against a local attacker who can write `<home>/`, because such an attacker
//! already owns the WAL, the config and the key itself. C4 is a guard against
//! a remote counterparty changing its declared contract after approval, and
//! that is the whole of what it claims.
//!
//! ## Canonicalisation
//!
//! Serialisation is done by an explicit key-sorting walk rather than by
//! `serde_json::to_vec`. `serde_json` orders map keys only while the
//! `preserve_order` feature is off, and cargo features are additive across the
//! dependency graph — any crate enabling it would silently switch `Map` to
//! insertion order and invalidate every stored pin. A security primitive
//! should not inherit that from an unrelated dependency.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::mcp::client::McpTool;

type HmacSha256 = Hmac<Sha256>;

/// Relative location of the pin store inside the neoth home.
const PIN_FILE: &str = "mcp_tool_pins.json";
/// Stable sibling used to serialize cross-process pin-store transactions.
const PIN_LOCK_FILE: &str = "mcp_tool_pins.lock";

/// Same-process tier for the mutex-first ordering required by `locked_file`.
static PIN_STORE_MUTEX: Mutex<()> = Mutex::new(());

const LOCK_RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(50);
const LOCK_GIVE_UP_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// What the guardian decided about one tool sighting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerdict {
    /// Tool was already pinned and the fingerprint still matches.
    Unchanged,
    /// First sighting — the fingerprint was recorded (trust on first use).
    Pinned,
    /// The tool's declared contract changed after registration. The call must
    /// not proceed.
    Violation {
        /// Which facet moved, for an operator-readable refusal.
        detail: String,
    },
}

impl PinVerdict {
    /// A call may proceed only when the contract is the one that was approved.
    #[must_use]
    pub fn permits_call(&self) -> bool {
        !matches!(self, PinVerdict::Violation { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PinRecord {
    fingerprint: String,
    first_seen_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct PinStore {
    /// `"<server>\u{1f}<tool>"` → record. A flat map keeps the file diffable
    /// and avoids a nested shape whose merge semantics nobody needs yet.
    pins: BTreeMap<String, PinRecord>,
}

fn load_pin_store(path: &Path) -> Result<(bool, PinStore)> {
    let Some(raw) = read_private_pin_store(path)? else {
        return Ok((false, PinStore::default()));
    };
    let store = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "MCP tool pin store {} is malformed — refusing to continue unpinned; \
             inspect it before removing it",
            path.display()
        )
    })?;
    Ok((true, store))
}

fn lock_path(path: &Path) -> PathBuf {
    path.with_file_name(PIN_LOCK_FILE)
}

struct PrivateParent {
    _directory: std::fs::File,
    #[cfg(windows)]
    _ancestor_guards: Vec<std::fs::File>,
}

#[cfg(windows)]
fn open_windows_directory_chain(path: &Path) -> Result<(std::fs::File, Vec<std::fs::File>)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Component, Prefix};

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix)) => prefix,
        _ => anyhow::bail!(
            "MCP tool pin parent must use an absolute local Windows path: {}",
            path.display()
        ),
    };
    anyhow::ensure!(
        matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)),
        "MCP tool pin parent must not use a UNC/device namespace: {}",
        path.display()
    );
    anyhow::ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "MCP tool pin parent must use an absolute local Windows path: {}",
        path.display()
    );

    let mut current = PathBuf::from(prefix.as_os_str());
    current.push(std::path::MAIN_SEPARATOR_STR);
    let mut guards = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "MCP tool pin parent must be normalized without dot components: {}",
                path.display()
            );
        };
        current.push(name);
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
            .with_context(|| {
                format!(
                    "open MCP tool pin namespace component without following reparse points {}",
                    current.display()
                )
            })?;
        anyhow::ensure!(
            directory.metadata()?.is_dir(),
            "MCP tool pin namespace component is not a directory: {}",
            current.display()
        );
        verify_windows_non_reparse(&directory, &current, "MCP tool pin namespace component")?;
        guards.push(directory);
    }

    let directory = guards
        .pop()
        .context("MCP tool pin parent path contains no directory component")?;
    Ok((directory, guards))
}

fn open_private_parent(path: &Path) -> Result<PrivateParent> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("MCP tool pin store path has no parent directory")?;

    #[cfg(unix)]
    let directory = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
        options.open(parent).with_context(|| {
            format!(
                "open MCP tool pin parent without following links {}",
                parent.display()
            )
        })?
    };
    #[cfg(windows)]
    let (directory, ancestor_guards) = open_windows_directory_chain(parent)?;
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("owner-private MCP tool pin storage is unsupported on this target");
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect MCP tool pin parent {}", parent.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "MCP tool pin parent is not a directory: {}",
        parent.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path_metadata = std::fs::symlink_metadata(parent)
            .with_context(|| format!("inspect MCP tool pin parent path {}", parent.display()))?;
        anyhow::ensure!(
            path_metadata.is_dir()
                && path_metadata.dev() == metadata.dev()
                && path_metadata.ino() == metadata.ino(),
            "MCP tool pin parent path changed or is a link: {}",
            parent.display()
        );
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "MCP tool pin parent is not owned by the current user: {}",
            parent.display()
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "MCP tool pin parent is accessible by group or other users: {}",
            parent.display()
        );
        // Child opens below are path-based on Unix. Protect the already-open
        // private parent from prefix replacement by walking every namespace
        // authority up to `/`: each ancestor must be current-user/root-owned,
        // and any group/other-writable ancestor must be sticky (for example
        // `/tmp`). Same-UID processes stay outside this guard's stated threat
        // boundary because they also own the instance HMAC key and WAL.
        anyhow::ensure!(
            parent.is_absolute()
                && parent.components().all(|component| {
                    matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }),
            "MCP tool pin parent must be an absolute normalized path: {}",
            parent.display()
        );
        for ancestor in parent.ancestors().skip(1) {
            let ancestor_metadata = std::fs::symlink_metadata(ancestor).with_context(|| {
                format!(
                    "inspect MCP tool pin namespace ancestor {}",
                    ancestor.display()
                )
            })?;
            let ancestor_mode = ancestor_metadata.permissions().mode();
            anyhow::ensure!(
                ancestor_metadata.is_dir()
                    && (ancestor_metadata.uid() == unsafe { libc::geteuid() }
                        || ancestor_metadata.uid() == 0)
                    && (ancestor_mode & 0o022 == 0 || ancestor_mode & 0o1000 != 0),
                "MCP tool pin namespace can be replaced by another user: {}",
                ancestor.display()
            );
        }
    }
    #[cfg(windows)]
    {
        verify_windows_non_reparse(&directory, parent, "MCP tool pin parent")?;
        crate::wal::win_native::verify_private_directory_handle_dacl(&directory).with_context(
            || {
                format!(
                    "verify private MCP tool pin parent DACL {}",
                    parent.display()
                )
            },
        )?;
    }

    Ok(PrivateParent {
        _directory: directory,
        #[cfg(windows)]
        _ancestor_guards: ancestor_guards,
    })
}

#[cfg(windows)]
fn verify_windows_non_reparse(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a live kernel handle and `information` is correctly
    // sized writable storage observed only after Win32 reports success.
    anyhow::ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) }
            != 0,
        "inspect {label} reparse attributes {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful Win32 call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    anyhow::ensure!(
        information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{label} must not be a Windows reparse point: {}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
struct OwnedSecurityDescriptor(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo returned this LocalAlloc-owned descriptor.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(
                    self.0 as windows_sys::Win32::Foundation::HLOCAL,
                )
            };
        }
    }
}

#[cfg(windows)]
fn verify_private_file_owner(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, IsValidAcl,
        IsValidSid, OWNER_SECURITY_INFORMATION,
    };

    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY:
    // - `file` is the live lock handle and GENERIC_READ carries READ_CONTROL.
    // - all requested owner/DACL out-pointers are valid writable storage.
    // - the returned LocalAlloc descriptor is guarded immediately below.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = OwnedSecurityDescriptor(descriptor);
    anyhow::ensure!(
        code == ERROR_SUCCESS,
        "read {label} owner {}: {}",
        path.display(),
        std::io::Error::from_raw_os_error(code as i32)
    );
    anyhow::ensure!(
        !descriptor.is_null() && !owner.is_null() && !dacl.is_null(),
        "{label} has incomplete owner/DACL security metadata: {}",
        path.display()
    );
    // SAFETY: dacl belongs to the guarded descriptor returned above.
    anyhow::ensure!(
        unsafe { IsValidAcl(dacl) } != 0,
        "{label} contains an invalid DACL: {}",
        path.display()
    );

    let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: verify_private_file_handle already proved this exact handle has
    // one structurally valid allow ACE. Index zero is therefore in bounds.
    anyhow::ensure!(
        unsafe { GetAce(dacl, 0, &mut ace) } != 0 && !ace.is_null(),
        "read {label} owner ACE {}",
        path.display()
    );
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    // SAFETY: IsValidAcl accepted the ACL and GetAce returned an in-range ACE;
    // copy only its fixed header before using the advertised size.
    let header = unsafe { std::ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
    anyhow::ensure!(
        usize::from(header.AceSize) >= sid_offset + 8,
        "{label} owner ACE is too short for a SID: {}",
        path.display()
    );
    // SAFETY: the private-DACL proof above validated the complete ACE and its
    // embedded SID before this second owner-bound descriptor read.
    let trustee = unsafe { ace.cast::<u8>().add(sid_offset) }.cast::<std::ffi::c_void>();
    // SAFETY: owner points into the guarded descriptor; trustee points into its
    // validated first ACE. IsValidSid only reads either value.
    anyhow::ensure!(
        unsafe { IsValidSid(owner) } != 0 && unsafe { IsValidSid(trustee) } != 0,
        "{label} contains an invalid owner or trustee SID: {}",
        path.display()
    );
    // The DACL verifier bound `trustee` to the current process TokenUser. Owner
    // equality therefore proves current-user ownership without path re-open.
    // SAFETY: both SIDs were validated immediately above.
    anyhow::ensure!(
        unsafe { EqualSid(owner, trustee) } != 0,
        "{label} is not owned by the current user: {}",
        path.display()
    );
    Ok(())
}

fn verify_private_regular_file(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path_metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspect {label} path {}", path.display()))?;
        anyhow::ensure!(
            path_metadata.is_file()
                && path_metadata.dev() == metadata.dev()
                && path_metadata.ino() == metadata.ino(),
            "{label} path changed or is a link: {}",
            path.display()
        );
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "{label} is not owned by the current user: {}",
            path.display()
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "{label} is accessible by group or other users: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        verify_windows_non_reparse(file, path, label)?;
        crate::wal::win_native::verify_private_file_handle(file)
            .with_context(|| format!("verify private {label} {}", path.display()))?;
        verify_private_file_owner(file, path, label)?;
        crate::wal::win_native::verify_private_file_handle(file).with_context(|| {
            format!(
                "re-verify private {label} after owner check {}",
                path.display()
            )
        })?;
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("owner-private MCP tool pin storage is unsupported on this target");

    Ok(())
}

fn read_private_pin_store(path: &Path) -> Result<Option<Vec<u8>>> {
    let parent = open_private_parent(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "open MCP tool pin store without following links {}",
                    path.display()
                )
            });
        }
    };
    verify_private_regular_file(&file, path, "MCP tool pin store")?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .with_context(|| format!("read MCP tool pin store {}", path.display()))?;
    verify_private_regular_file(&file, path, "MCP tool pin store")?;
    drop(parent);
    Ok(Some(raw))
}

struct StoreLock {
    _parent: PrivateParent,
    _file: std::fs::File,
}

fn try_acquire_store_lock(path: &Path) -> Result<Option<std::fs::File>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| {
                format!(
                    "open MCP tool pin lock without following links {}",
                    path.display()
                )
            })?;
        // SAFETY: `file` owns a live descriptor for the stable lock entry.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(Some(file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error).with_context(|| format!("lock MCP tool pin store {}", path.display()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const ERROR_SHARING_VIOLATION: i32 = 32;

        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "open MCP tool pin lock without following reparse points {}",
                    path.display()
                )
            }),
        }
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("owner-private MCP tool pin locking is unsupported on this target");
}

fn acquire_store_lock(path: &Path) -> Result<StoreLock> {
    let parent = open_private_parent(path)?;
    let lock_path = lock_path(path);
    match crate::util::atomic_write::write_private_create_new(&lock_path, b"") {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "create owner-private MCP tool pin lock {}",
                    lock_path.display()
                )
            });
        }
    }

    let started = std::time::Instant::now();
    loop {
        if let Some(lock) = try_acquire_store_lock(&lock_path)? {
            verify_private_regular_file(&lock, &lock_path, "MCP tool pin lock")?;
            return Ok(StoreLock {
                _parent: parent,
                _file: lock,
            });
        }
        anyhow::ensure!(
            started.elapsed() < LOCK_GIVE_UP_AFTER,
            "MCP tool pin store lock {} held by another process for >5s",
            lock_path.display()
        );
        std::thread::sleep(LOCK_RETRY_EVERY);
    }
}

fn pin_key(server: &str, tool: &str) -> String {
    format!("{server}\u{1f}{tool}")
}

/// Canonical byte encoding of a JSON value: object keys sorted, no whitespace,
/// arrays in order. Written out explicitly so the encoding cannot change
/// underneath us (see the module note on `preserve_order`).
fn canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        // `serde_json`'s Display for numbers is already the shortest
        // round-trippable form; reproducing it by hand would be a worse bug
        // surface than reusing it.
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            out.push_str(&serde_json::Value::String(s.clone()).to_string());
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                canonical_json(v, out);
            }
            out.push('}');
        }
    }
}

/// Domain-separated, length-framed HMAC over everything a caller's trust
/// decision depends on.
///
/// Length framing matters: without it a tool named `"ab"` with description
/// `"c"` and one named `"a"` with description `"bc"` would hash identically,
/// letting a server rename around a pin.
fn fingerprint(key: &[u8], server: &str, tool: &McpTool) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow::anyhow!("hmac key rejected: {e}"))?;
    mac.update(b"neoth/mcp-tool-pin/v1\0");

    let mut field = |bytes: &[u8]| {
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(bytes);
    };
    field(server.as_bytes());
    field(tool.name.as_bytes());
    field(tool.description.as_deref().unwrap_or("").as_bytes());

    let mut schema = String::new();
    canonical_json(&tool.input_schema, &mut schema);
    field(schema.as_bytes());

    // The annotations are the auto-approval surface — see the module note.
    // NOTE: `ToolAnnotations` keeps only the two hints SmartApprove acts on and
    // drops unknown fields, so the pin covers exactly the surface that drives a
    // trust decision today. A hint added to the struct later is covered
    // automatically; one honoured elsewhere without being parsed here would not
    // be, so new auto-approval inputs belong in this struct.
    let annotations = serde_json::to_value(&tool.annotations)
        .context("serialize MCP tool annotations for fingerprint")?;
    let mut annotations_canonical = String::new();
    canonical_json(&annotations, &mut annotations_canonical);
    field(annotations_canonical.as_bytes());

    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

/// Pin store bound to one neoth home.
pub struct McpGuardian {
    _home_guard: PrivateParent,
    path: PathBuf,
    key: Vec<u8>,
    store: PinStore,
    baseline: PinStore,
    store_existed_at_open: bool,
    observations: BTreeMap<String, PinRecord>,
}

impl McpGuardian {
    /// Open (or start) the pin store for `home`.
    ///
    /// Fails closed on an unreadable or malformed store rather than starting
    /// from an empty map: silently re-pinning everything is exactly what an
    /// attacker who can truncate the file would want.
    pub fn open(home: &Path) -> Result<Self> {
        let path = home.join(PIN_FILE);
        let home_guard = open_private_parent(&path)?;
        let key = crate::wal::scan::load_home_hmac_keys(home)
            .context("load instance HMAC identity for MCP tool pinning")?
            .into_iter()
            .next()
            .context(
                "no instance HMAC key found — MCP tool pinning cannot verify a schema without \
                 the instance identity",
            )?;
        let (store_existed_at_open, store) = load_pin_store(&path)?;
        Ok(Self {
            _home_guard: home_guard,
            path,
            key,
            baseline: store.clone(),
            store,
            store_existed_at_open,
            observations: BTreeMap::new(),
        })
    }

    /// Check one tool sighting against its pin, recording it on first use.
    ///
    /// The caller must refuse the invocation when the verdict does not
    /// [`PinVerdict::permits_call`].
    pub fn check(&mut self, server: &str, tool: &McpTool, now_unix: i64) -> Result<PinVerdict> {
        let observed = fingerprint(&self.key, server, tool)?;
        let key = pin_key(server, &tool.name);
        match self.store.pins.get(&key).cloned() {
            Some(pinned) if pinned.fingerprint == observed => {
                self.observations.insert(key, pinned);
                Ok(PinVerdict::Unchanged)
            }
            Some(pinned) => {
                self.observations.insert(key, pinned.clone());
                Ok(PinVerdict::Violation {
                    detail: format!(
                        "tool '{tool}' on server '{server}' changed its declared contract after \
                         registration (pinned {pinned_short}… on first use, now {observed_short}…); \
                         the call is refused",
                        tool = tool.name,
                        pinned_short = &pinned.fingerprint[..16.min(pinned.fingerprint.len())],
                        observed_short = &observed[..16.min(observed.len())],
                    ),
                })
            }
            None => {
                let record = PinRecord {
                    fingerprint: observed,
                    first_seen_unix: now_unix,
                };
                self.store.pins.insert(key.clone(), record.clone());
                self.observations.insert(key, record);
                Ok(PinVerdict::Pinned)
            }
        }
    }

    /// Validate and persist this session's observations as one locked RMW.
    ///
    /// The store is re-read only after both lock tiers are held. Unrelated pins
    /// added by another process are retained; a competing fingerprint for the
    /// same tool, or mutation/removal of anything in our opening snapshot,
    /// aborts rather than making a stale writer authoritative.
    pub fn flush(&mut self) -> Result<()> {
        if self.observations.is_empty() {
            return Ok(());
        }

        let _process_guard = PIN_STORE_MUTEX
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP tool pin store mutex poisoned"))?;
        let _file_guard = acquire_store_lock(&self.path)?;
        let (latest_exists, mut latest) = load_pin_store(&self.path)?;

        anyhow::ensure!(
            !self.store_existed_at_open || latest_exists,
            "MCP tool pin store {} disappeared after it was opened — refusing a stale merge",
            self.path.display()
        );
        for (key, expected) in &self.baseline.pins {
            match latest.pins.get(key) {
                Some(actual) if actual == expected => {}
                Some(_) => anyhow::bail!(
                    "MCP tool pin {key:?} changed after the store was opened — refusing a stale merge"
                ),
                None => anyhow::bail!(
                    "MCP tool pin {key:?} disappeared after the store was opened — refusing a stale merge"
                ),
            }
        }

        let mut changed = false;
        for (key, observed) in &self.observations {
            match latest.pins.get(key) {
                Some(current) if current.fingerprint == observed.fingerprint => {}
                Some(_) => anyhow::bail!(
                    "MCP tool pin conflict for {key:?}: another process pinned a different \
                     contract; refusing to overwrite either observation"
                ),
                None => {
                    latest.pins.insert(key.clone(), observed.clone());
                    changed = true;
                }
            }
        }

        let expected_bytes = if changed {
            let encoded =
                serde_json::to_vec_pretty(&latest).context("serialize MCP tool pin store")?;
            crate::util::atomic_write::atomic_write_private(&self.path, &encoded)
                .with_context(|| format!("persist MCP tool pin store {}", self.path.display()))?;
            Some(encoded)
        } else {
            None
        };
        crate::util::atomic_write::sync_parent_directory_required(&self.path).with_context(
            || {
                format!(
                    "durably commit MCP tool pin store directory {}",
                    self.path.display()
                )
            },
        )?;

        let raw = read_private_pin_store(&self.path)?.with_context(|| {
            format!(
                "MCP tool pin store {} disappeared during write read-back",
                self.path.display()
            )
        })?;
        if let Some(expected_bytes) = expected_bytes {
            anyhow::ensure!(
                raw == expected_bytes,
                "MCP tool pin store {} failed exact write read-back",
                self.path.display()
            );
        }
        let read_back: PinStore = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "MCP tool pin store {} became malformed during write read-back",
                self.path.display()
            )
        })?;
        anyhow::ensure!(
            read_back == latest,
            "MCP tool pin store {} failed semantic write read-back",
            self.path.display()
        );

        self.store = latest;
        self.baseline = self.store.clone();
        self.store_existed_at_open = true;
        self.observations.clear();
        Ok(())
    }

    /// How many tools are currently pinned (operator diagnostics + tests).
    #[must_use]
    pub fn pinned_count(&self) -> usize {
        self.store.pins.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::client::ToolAnnotations;
    use tempfile::tempdir;

    fn home_with_key() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(dir.path()).unwrap();
        let wal = dir.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join("hmac.key"), [7u8; 32]).unwrap();
        dir
    }

    fn tool(name: &str, schema: serde_json::Value) -> McpTool {
        McpTool {
            name: name.to_string(),
            description: Some("does a thing".into()),
            input_schema: schema,
            annotations: None,
        }
    }

    #[test]
    fn first_sighting_pins_and_an_identical_redeclaration_passes() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let t = tool("search", serde_json::json!({"type": "object"}));

        assert_eq!(g.check("srv", &t, 1).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.check("srv", &t, 2).unwrap(), PinVerdict::Unchanged);
        assert_eq!(g.pinned_count(), 1);
    }

    #[test]
    fn a_changed_input_schema_blocks_the_call() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        g.check(
            "srv",
            &tool("search", serde_json::json!({"type": "object"})),
            1,
        )
        .unwrap();

        let swapped = tool(
            "search",
            serde_json::json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
        );
        let verdict = g.check("srv", &swapped, 2).unwrap();
        assert!(matches!(verdict, PinVerdict::Violation { .. }));
        assert!(!verdict.permits_call());
    }

    #[test]
    fn flipping_destructive_to_read_only_blocks_the_call() {
        // The auto-approval attack: SmartApprove approves by declared EFFECT,
        // so annotations must be inside the fingerprint. A guard that hashed
        // only input_schema would wave this through.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let mut t = tool("run", serde_json::json!({"type": "object"}));
        t.annotations = Some(ToolAnnotations {
            read_only_hint: Some(false),
            destructive_hint: Some(true),
        });
        assert_eq!(g.check("srv", &t, 1).unwrap(), PinVerdict::Pinned);

        t.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
        });
        assert!(
            !g.check("srv", &t, 2).unwrap().permits_call(),
            "an effect-annotation flip must block — it is the auto-approval surface"
        );
    }

    #[test]
    fn key_reordering_in_the_schema_is_not_a_violation() {
        // Canonicalisation exists so a server that serialises its schema with
        // different key order does not look like an attacker.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool(
            "search",
            serde_json::json!({"type": "object", "title": "t", "extra": [1, 2]}),
        );
        let b = tool(
            "search",
            serde_json::json!({"extra": [1, 2], "title": "t", "type": "object"}),
        );
        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.check("srv", &b, 2).unwrap(), PinVerdict::Unchanged);
    }

    #[test]
    fn array_order_still_matters() {
        // Canonicalisation sorts object KEYS, never array elements — element
        // order is semantic in JSON Schema (`required`, `enum`, `prefixItems`).
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool("x", serde_json::json!({"required": ["a", "b"]}));
        let b = tool("x", serde_json::json!({"required": ["b", "a"]}));
        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        assert!(!g.check("srv", &b, 2).unwrap().permits_call());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_name_and_description() {
        // Without length framing, ("ab", "c") and ("a", "bc") would collide.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let mut a = tool("ab", serde_json::json!({}));
        a.description = Some("c".into());
        let mut b = tool("ab", serde_json::json!({}));
        b.description = Some("".into());

        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        // Same key (server+name), different framing → must not match.
        assert!(!g.check("srv", &b, 2).unwrap().permits_call());
    }

    #[test]
    fn pins_survive_a_reopen() {
        let home = home_with_key();
        let t = tool("search", serde_json::json!({"type": "object"}));
        {
            let mut g = McpGuardian::open(home.path()).unwrap();
            g.check("srv", &t, 1).unwrap();
            g.flush().unwrap();
        }
        let mut reopened = McpGuardian::open(home.path()).unwrap();
        assert_eq!(reopened.pinned_count(), 1);
        assert_eq!(reopened.check("srv", &t, 2).unwrap(), PinVerdict::Unchanged);
    }

    const CHILD_HOME: &str = "NEOTH_MCP_GUARDIAN_CHILD_HOME";
    const CHILD_READY: &str = "NEOTH_MCP_GUARDIAN_CHILD_READY";
    const CHILD_START: &str = "NEOTH_MCP_GUARDIAN_CHILD_START";
    const CHILD_SERVER: &str = "NEOTH_MCP_GUARDIAN_CHILD_SERVER";
    const CHILD_TOOL: &str = "NEOTH_MCP_GUARDIAN_CHILD_TOOL";
    const CHILD_SCHEMA: &str = "NEOTH_MCP_GUARDIAN_CHILD_SCHEMA";

    fn spawn_guardian_child(
        home: &Path,
        ready: &Path,
        start: &Path,
        server: &str,
        tool_name: &str,
        schema: &str,
    ) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security::mcp_guardian::tests::cross_process_flush_helper",
                "--nocapture",
            ])
            .env(CHILD_HOME, home)
            .env(CHILD_READY, ready)
            .env(CHILD_START, start)
            .env(CHILD_SERVER, server)
            .env(CHILD_TOOL, tool_name)
            .env(CHILD_SCHEMA, schema)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn release_children_after_ready(
        first: &mut std::process::Child,
        first_ready: &Path,
        second: &mut std::process::Child,
        second_ready: &Path,
        start: &Path,
    ) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !first_ready.exists() || !second_ready.exists() {
            assert!(
                first.try_wait().unwrap().is_none() && second.try_wait().unwrap().is_none(),
                "guardian child exited before reaching the flush barrier"
            );
            if std::time::Instant::now() >= deadline {
                let _ = first.kill();
                let _ = second.kill();
                panic!("guardian children did not reach the flush barrier within 15s");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::write(start, b"go").unwrap();
    }

    fn child_output(output: &std::process::Output) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    fn cross_process_flush_helper() {
        let Some(home) = std::env::var_os(CHILD_HOME) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(CHILD_READY).unwrap());
        let start = PathBuf::from(std::env::var_os(CHILD_START).unwrap());
        let server = std::env::var(CHILD_SERVER).unwrap();
        let tool_name = std::env::var(CHILD_TOOL).unwrap();
        let schema = serde_json::from_str(&std::env::var(CHILD_SCHEMA).unwrap()).unwrap();

        let mut guardian = McpGuardian::open(Path::new(&home)).unwrap();
        assert_eq!(
            guardian
                .check(&server, &tool(&tool_name, schema), 10)
                .unwrap(),
            PinVerdict::Pinned
        );
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !start.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent did not release guardian child within 15s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        guardian.flush().unwrap();
    }

    #[test]
    fn cross_process_guardians_merge_unrelated_first_sightings() {
        let home = home_with_key();
        let start = home.path().join("children.start");
        let first_ready = home.path().join("first.ready");
        let second_ready = home.path().join("second.ready");
        let mut first = spawn_guardian_child(
            home.path(),
            &first_ready,
            &start,
            "srv-a",
            "search",
            r#"{"type":"object"}"#,
        );
        let mut second = spawn_guardian_child(
            home.path(),
            &second_ready,
            &start,
            "srv-b",
            "lookup",
            r#"{"type":"string"}"#,
        );
        release_children_after_ready(&mut first, &first_ready, &mut second, &second_ready, &start);
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert!(first.status.success(), "{}", child_output(&first));
        assert!(second.status.success(), "{}", child_output(&second));

        let mut reopened = McpGuardian::open(home.path()).unwrap();
        assert_eq!(reopened.pinned_count(), 2);
        assert_eq!(
            reopened
                .check(
                    "srv-a",
                    &tool("search", serde_json::json!({"type": "object"})),
                    30,
                )
                .unwrap(),
            PinVerdict::Unchanged
        );
        assert_eq!(
            reopened
                .check(
                    "srv-b",
                    &tool("lookup", serde_json::json!({"type": "string"})),
                    30,
                )
                .unwrap(),
            PinVerdict::Unchanged
        );
    }

    #[test]
    fn cross_process_conflicting_first_sightings_fail_closed() {
        let home = home_with_key();
        let start = home.path().join("children.start");
        let object_ready = home.path().join("object.ready");
        let string_ready = home.path().join("string.ready");
        let mut object = spawn_guardian_child(
            home.path(),
            &object_ready,
            &start,
            "srv",
            "search",
            r#"{"type":"object"}"#,
        );
        let mut string = spawn_guardian_child(
            home.path(),
            &string_ready,
            &start,
            "srv",
            "search",
            r#"{"type":"string"}"#,
        );
        release_children_after_ready(
            &mut object,
            &object_ready,
            &mut string,
            &string_ready,
            &start,
        );
        let object = object.wait_with_output().unwrap();
        let string = string.wait_with_output().unwrap();
        assert_ne!(
            object.status.success(),
            string.status.success(),
            "exactly one competing contract may commit\nobject {}\nstring {}",
            child_output(&object),
            child_output(&string)
        );
        let loser = if object.status.success() {
            &string
        } else {
            &object
        };
        assert!(
            child_output(loser).contains("pin conflict"),
            "loser must report a semantic conflict: {}",
            child_output(loser)
        );

        let mut reopened = McpGuardian::open(home.path()).unwrap();
        let object_verdict = reopened
            .check(
                "srv",
                &tool("search", serde_json::json!({"type": "object"})),
                30,
            )
            .unwrap();
        let string_verdict = reopened
            .check(
                "srv",
                &tool("search", serde_json::json!({"type": "string"})),
                30,
            )
            .unwrap();
        assert_ne!(
            object_verdict.permits_call(),
            string_verdict.permits_call(),
            "persisted winner must remain authoritative and loser must be blocked"
        );
    }

    #[test]
    fn changed_opening_snapshot_is_not_overwritten_by_a_stale_flush() {
        let home = home_with_key();
        let original = tool("search", serde_json::json!({"type": "object"}));
        let mut initial = McpGuardian::open(home.path()).unwrap();
        initial.check("srv", &original, 1).unwrap();
        initial.flush().unwrap();

        let mut stale = McpGuardian::open(home.path()).unwrap();
        assert_eq!(
            stale.check("srv", &original, 2).unwrap(),
            PinVerdict::Unchanged
        );
        let path = home.path().join(PIN_FILE);
        let (_, mut tampered) = load_pin_store(&path).unwrap();
        tampered
            .pins
            .get_mut(&pin_key("srv", "search"))
            .unwrap()
            .fingerprint = "00".repeat(32);
        let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
        std::fs::write(&path, &tampered_bytes).unwrap();

        let error = stale.flush().unwrap_err();
        assert!(format!("{error:#}").contains("changed after the store was opened"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            tampered_bytes,
            "fail-closed stale writer must not publish over conflicting bytes"
        );
    }

    #[test]
    fn transaction_lock_is_owner_private() {
        let home = home_with_key();
        let mut guardian = McpGuardian::open(home.path()).unwrap();
        guardian
            .check(
                "srv",
                &tool("search", serde_json::json!({"type": "object"})),
                1,
            )
            .unwrap();
        guardian.flush().unwrap();

        let path = home.path().join(PIN_LOCK_FILE);
        let file = std::fs::File::open(&path).unwrap();
        verify_private_regular_file(&file, &path, "MCP tool pin lock").unwrap();
    }

    #[test]
    fn a_second_lock_handle_cannot_enter_while_the_first_is_live() {
        let home = home_with_key();
        let pin_path = home.path().join(PIN_FILE);
        let first = acquire_store_lock(&pin_path).unwrap();
        assert!(
            try_acquire_store_lock(&lock_path(&pin_path))
                .unwrap()
                .is_none(),
            "the stable lock entry must exclude a second writer"
        );
        drop(first);
        assert!(
            try_acquire_store_lock(&lock_path(&pin_path))
                .unwrap()
                .is_some(),
            "dropping the lock handle must release the transaction"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_existing_store_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let home = home_with_key();
        let mut guardian = McpGuardian::open(home.path()).unwrap();
        guardian
            .check(
                "srv",
                &tool("search", serde_json::json!({"type": "object"})),
                1,
            )
            .unwrap();
        guardian.flush().unwrap();
        let path = home.path().join(PIN_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let error = McpGuardian::open(home.path())
            .err()
            .expect("broad pin-store permissions must be rejected");
        assert!(error.to_string().contains("group or other users"));
    }

    #[cfg(unix)]
    #[test]
    fn pin_store_and_lock_symlinks_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = home_with_key();
        let target = home.path().join("target.json");
        std::fs::write(&target, b"{\"pins\":{}}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, home.path().join(PIN_FILE)).unwrap();
        assert!(McpGuardian::open(home.path()).is_err());

        std::fs::remove_file(home.path().join(PIN_FILE)).unwrap();
        symlink(&target, home.path().join(PIN_LOCK_FILE)).unwrap();
        let mut guardian = McpGuardian::open(home.path()).unwrap();
        guardian
            .check(
                "srv",
                &tool("search", serde_json::json!({"type": "object"})),
                1,
            )
            .unwrap();
        assert!(guardian.flush().is_err());
    }

    #[test]
    fn a_malformed_store_fails_closed_instead_of_starting_empty() {
        // Truncating the file must not silently re-pin whatever the server
        // currently claims.
        let home = home_with_key();
        crate::util::atomic_write::atomic_write_private(&home.path().join(PIN_FILE), b"{ not json")
            .unwrap();
        assert!(
            McpGuardian::open(home.path()).is_err(),
            "a malformed pin store must refuse to open, not start unpinned"
        );
    }

    #[test]
    fn the_same_tool_name_on_two_servers_is_pinned_separately() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool("search", serde_json::json!({"type": "object"}));
        let b = tool("search", serde_json::json!({"type": "string"}));
        assert_eq!(g.check("srv-a", &a, 1).unwrap(), PinVerdict::Pinned);
        // Different server, same name: its own first sighting, not a violation.
        assert_eq!(g.check("srv-b", &b, 2).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.pinned_count(), 2);
    }
}
