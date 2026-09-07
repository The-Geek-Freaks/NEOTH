//! Native, capability-bound SQLite VFS for the Windows Context Store.
//!
//! It remains crate-private: `ContextStore` obtains a
//! [`PinnedContextDirectory`] from a trusted component walk before registering
//! it. Accepting a `Path` here would make SQLite's later sidecar opens an
//! ambient namespace operation again.

#![cfg(windows)]

#[path = "windows_vfs/handles.rs"]
mod handles;

#[cfg(test)]
use std::cell::Cell;
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::File,
    mem::size_of,
    os::windows::{fs::FileExt, io::AsRawHandle},
    ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, ffi};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
};

pub(crate) use handles::PinnedContextDirectory;
use handles::{ContextLeaf, FileIdentity};

const SQLITE_OK: c_int = ffi::SQLITE_OK;
const SQLITE_BUSY: c_int = ffi::SQLITE_BUSY;
const SQLITE_CANTOPEN: c_int = ffi::SQLITE_CANTOPEN;
const SQLITE_FULL: c_int = ffi::SQLITE_FULL;
const SQLITE_IOERR: c_int = ffi::SQLITE_IOERR;
const SQLITE_IOERR_READ: c_int = ffi::SQLITE_IOERR_READ;
const SQLITE_IOERR_SHORT_READ: c_int = ffi::SQLITE_IOERR_SHORT_READ;
const SQLITE_IOERR_WRITE: c_int = ffi::SQLITE_IOERR_WRITE;
const SQLITE_IOERR_FSYNC: c_int = ffi::SQLITE_IOERR_FSYNC;
const SQLITE_IOERR_TRUNCATE: c_int = ffi::SQLITE_IOERR_TRUNCATE;
const SQLITE_IOERR_FSTAT: c_int = ffi::SQLITE_IOERR_FSTAT;
const SQLITE_IOERR_LOCK: c_int = ffi::SQLITE_IOERR_LOCK;
const SQLITE_IOERR_UNLOCK: c_int = ffi::SQLITE_IOERR_UNLOCK;
const SQLITE_IOERR_CHECKRESERVEDLOCK: c_int = ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
const SQLITE_IOERR_DELETE: c_int = ffi::SQLITE_IOERR_DELETE;
const SQLITE_IOERR_DELETE_NOENT: c_int = ffi::SQLITE_IOERR_DELETE_NOENT;
const SQLITE_IOERR_SHMOPEN: c_int = ffi::SQLITE_IOERR_SHMOPEN;
const SQLITE_IOERR_SHMMAP: c_int = ffi::SQLITE_IOERR_SHMMAP;
const SQLITE_IOERR_SHMLOCK: c_int = ffi::SQLITE_IOERR_SHMLOCK;
const SQLITE_NOTFOUND: c_int = ffi::SQLITE_NOTFOUND;

const PENDING_BYTE: u64 = 0x4000_0000;
const RESERVED_BYTE: u64 = PENDING_BYTE + 1;
const SHARED_FIRST: u64 = PENDING_BYTE + 2;
const SHARED_SIZE: u64 = 510;
const ALLOCATION_GRANULARITY: u64 = 64 * 1024;
static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(1);
// Registrations own SQLite's static VFS structures for the process lifetime.
// Production must therefore remain tightly bounded. Native acceptance gives
// each case a distinct private directory so WAL, quota, and lock state cannot
// bleed between cases; its finite test-only allowance covers that fixture set.
#[cfg(test)]
const MAX_REGISTERED_CONTEXT_ROOTS: usize = 32;
#[cfg(not(test))]
const MAX_REGISTERED_CONTEXT_ROOTS: usize = 4;
static REGISTERED_VFS: OnceLock<Mutex<BTreeMap<FileIdentity, RegisteredVfs>>> = OnceLock::new();

// This seam is deliberately limited to the kernel-unlock result used by the
// raw VFS acceptance test below. It proves that an unlock failure cannot erase
// the corresponding in-memory ownership bit before the handle is dropped.
#[cfg(test)]
thread_local! {
    static TEST_FAIL_NEXT_UNLOCK: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

#[cfg(test)]
fn fail_next_unlock_for_test(offset: u64, len: u64) {
    TEST_FAIL_NEXT_UNLOCK.with(|failure| failure.set(Some((offset, len))));
}

struct RegisteredVfs {
    name: &'static CStr,
    state: &'static VfsState,
    max_bytes: u64,
}

/// Owns the registered callback table and the capability retained in `pAppData`.
///
/// The table is intentionally leaked after successful registration.  SQLite has
/// no lifetime token for a VFS callback table, and `sqlite3_vfs_unregister`
/// would be unsafe while any `Connection` still owns one of its files.
pub(crate) struct ContextStoreVfs {
    name: &'static CStr,
    state: &'static VfsState,
}

impl ContextStoreVfs {
    pub(crate) fn register(
        directory: PinnedContextDirectory,
        max_bytes: u64,
    ) -> std::io::Result<Self> {
        let root_identity = directory.identity();
        let registrations = REGISTERED_VFS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registrations = registrations
            .lock()
            .map_err(|_| std::io::Error::other("Context VFS registration lock poisoned"))?;
        if let Some(existing) = registrations.get(&root_identity) {
            if existing.max_bytes != max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "context root is already registered with a different quota",
                ));
            }
            return Ok(Self {
                name: existing.name,
                state: existing.state,
            });
        }
        if registrations.len() >= MAX_REGISTERED_CONTEXT_ROOTS {
            return Err(std::io::Error::other(
                "maximum number of process-lifetime Context VFS roots reached",
            ));
        }
        let id = NEXT_VFS_ID.fetch_add(1, Ordering::Relaxed);
        let name = Box::new(
            CString::new(format!("neoth-context-vfs-{id}")).expect("generated VFS name has no NUL"),
        );
        let mut state = Box::new(VfsState {
            directory,
            max_bytes,
            sizes: Mutex::new(BTreeMap::new()),
            shm: Mutex::new(BTreeMap::new()),
        });
        let mut raw = Box::new(ffi::sqlite3_vfs {
            iVersion: 3,
            szOsFile: size_of::<ContextFile>() as c_int,
            mxPathname: 64,
            pNext: ptr::null_mut(),
            zName: name.as_ptr(),
            pAppData: (&mut *state as *mut VfsState).cast(),
            xOpen: Some(x_open),
            xDelete: Some(x_delete),
            xAccess: Some(x_access),
            xFullPathname: Some(x_full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(x_randomness),
            xSleep: Some(x_sleep),
            xCurrentTime: Some(x_current_time),
            xGetLastError: None,
            xCurrentTimeInt64: Some(x_current_time_int64),
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        });
        // SAFETY: `raw`, `name`, and `state` are intentionally process-lifetime
        // allocations and the callbacks satisfy SQLite VFS ABI version 3.
        if unsafe { ffi::sqlite3_vfs_register(&mut *raw, 0) } != SQLITE_OK {
            return Err(std::io::Error::other(
                "sqlite3_vfs_register rejected Context VFS",
            ));
        }
        let name = Box::leak(name);
        let state = Box::leak(state);
        let _raw = Box::leak(raw);
        registrations.insert(
            root_identity,
            RegisteredVfs {
                name,
                state,
                max_bytes,
            },
        );
        Ok(Self { name, state })
    }

    pub(crate) fn name(&self) -> &str {
        self.name.to_str().expect("generated ASCII VFS name")
    }

    /// Handle-relative existence evidence and accounting for the exact Context
    /// objects. Display paths are never consulted after registration.
    pub(crate) fn footprint(&self) -> std::io::Result<(bool, u64, u64, u64)> {
        let length = |leaf| match self.state.directory.open_leaf(leaf, false, false) {
            Ok(file) => Ok(Some(file.metadata()?.len())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
        let main = length(ContextLeaf::Main)?;
        let wal = length(ContextLeaf::Wal)?.unwrap_or(0);
        let shm = length(ContextLeaf::Shm)?.unwrap_or(0);
        Ok((main.is_some(), main.unwrap_or(0), wal, shm))
    }

    pub(crate) fn checkpoint(&self, conn: &Connection) -> rusqlite::Result<()> {
        let _: (i64, i64, i64) = conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(())
    }
}

struct VfsState {
    directory: PinnedContextDirectory,
    max_bytes: u64,
    sizes: Mutex<BTreeMap<ContextLeaf, u64>>,
    shm: Mutex<BTreeMap<FileIdentity, Arc<Mutex<SharedMemory>>>>,
}

#[repr(C)]
struct ContextFile {
    base: ffi::sqlite3_file,
    inner: *mut Mutex<FileState>,
}

struct FileState {
    file: File,
    leaf: ContextLeaf,
    state: &'static VfsState,
    lock_level: c_int,
    shared_byte: u64,
    shared_locked: bool,
    reserved_locked: bool,
    pending_locked: bool,
    exclusive_locked: bool,
    id: u64,
    shm: Option<Arc<Mutex<SharedMemory>>>,
}

struct SharedMemory {
    file: File,
    maps: BTreeMap<u64, usize>,
    locks: BTreeMap<(u64, u64, bool), BTreeMap<u64, u32>>,
}

enum QuotaIoError {
    Full,
    Io,
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        for (_, address) in std::mem::take(&mut self.maps) {
            // SAFETY: each address was returned by MapViewOfFile and this Arc
            // owns the final mapping reference.
            unsafe { UnmapViewOfFile(address as *const c_void) };
        }
    }
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(x_close),
    xRead: Some(x_read),
    xWrite: Some(x_write),
    xTruncate: Some(x_truncate),
    xSync: Some(x_sync),
    xFileSize: Some(x_file_size),
    xLock: Some(x_lock),
    xUnlock: Some(x_unlock),
    xCheckReservedLock: Some(x_check_reserved),
    xFileControl: Some(x_file_control),
    xSectorSize: Some(x_sector_size),
    xDeviceCharacteristics: Some(x_device_characteristics),
    xShmMap: Some(x_shm_map),
    xShmLock: Some(x_shm_lock),
    xShmBarrier: Some(x_shm_barrier),
    xShmUnmap: Some(x_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};

unsafe fn vfs_state(vfs: *mut ffi::sqlite3_vfs) -> &'static VfsState {
    // SAFETY: only ContextStoreVfs registers these callbacks and pAppData
    // points to its process-lifetime VfsState allocation.
    unsafe { &*((*vfs).pAppData.cast::<VfsState>()) }
}
unsafe fn file_state<'callback>(
    file: &'callback mut ffi::sqlite3_file,
) -> Result<std::sync::MutexGuard<'callback, FileState>, ()> {
    // SAFETY: xOpen writes this field before assigning IO_METHODS; xClose
    // clears it exactly once after reclaiming its Box. The mutex serializes all
    // raw callbacks for this sqlite3_file without relying on SQLite's global
    // or connection threading configuration. The guard is callback-bounded.
    unsafe {
        let context = (file as *mut ffi::sqlite3_file).cast::<ContextFile>();
        (&*(*context).inner).lock().map_err(|_| ())
    }
}
macro_rules! locked_file_state {
    ($file:expr, $error:expr) => {
        match unsafe { file_state(&mut *$file) } {
            Ok(state) => state,
            Err(()) => return $error,
        }
    };
}
fn sqlite_name(name: *const c_char) -> Option<ContextLeaf> {
    if name.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_str().ok()?;
    ContextLeaf::parse_sqlite_name(name)
}

unsafe extern "C" fn x_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    out: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    if out.is_null() {
        return SQLITE_CANTOPEN;
    }
    // Clear this before any fallible name, quota, or handle operation. SQLite
    // can reuse its os-file allocation after a failed xOpen.
    unsafe { (*out).pMethods = ptr::null() };
    if name.is_null() || flags & (ffi::SQLITE_OPEN_TEMP_DB | ffi::SQLITE_OPEN_TRANSIENT_DB) != 0 {
        return SQLITE_CANTOPEN;
    }
    let Some(leaf) = sqlite_name(name) else {
        return SQLITE_CANTOPEN;
    };
    if leaf == ContextLeaf::Main && flags & ffi::SQLITE_OPEN_MAIN_DB == 0 {
        return SQLITE_CANTOPEN;
    }
    let state = unsafe { vfs_state(vfs) };
    let writable = flags & ffi::SQLITE_OPEN_READWRITE != 0;
    let create = flags & ffi::SQLITE_OPEN_CREATE != 0;
    let file = match state.directory.open_leaf(leaf, writable, create) {
        Ok(file) => file,
        Err(_) => return SQLITE_CANTOPEN,
    };
    let size = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(_) => return SQLITE_IOERR_FSTAT,
    };
    if state.record_size(leaf, size).is_err() {
        return SQLITE_FULL;
    }
    let inner = Mutex::new(FileState {
        file,
        leaf,
        state,
        lock_level: ffi::SQLITE_LOCK_NONE,
        shared_byte: SHARED_FIRST,
        shared_locked: false,
        reserved_locked: false,
        pending_locked: false,
        exclusive_locked: false,
        id: NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed),
        shm: None,
    });
    // SAFETY: SQLite supplies szOsFile bytes; ContextStoreVfs set it to this
    // exact type size and `out` is writable for the callback duration. The
    // Box allocation becomes the single `ContextFile::inner` owner; xClose
    // reclaims it exactly once after SQLite has stopped file callbacks.
    unsafe {
        ptr::write(
            out.cast::<ContextFile>(),
            ContextFile {
                base: ffi::sqlite3_file {
                    pMethods: &IO_METHODS,
                },
                inner: Box::into_raw(Box::new(inner)),
            },
        );
    }
    if !out_flags.is_null() {
        unsafe {
            *out_flags = flags;
        }
    }
    SQLITE_OK
}

unsafe extern "C" fn x_close(file: *mut ffi::sqlite3_file) -> c_int {
    if file.is_null() {
        return SQLITE_IOERR;
    }
    let raw = file.cast::<ContextFile>();
    let inner = unsafe { (*raw).inner };
    if !inner.is_null() {
        // SAFETY: xOpen created `inner` with Box::into_raw, and SQLite calls
        // xClose once after all callbacks on this sqlite3_file have ended.
        unsafe {
            drop(Box::from_raw(inner));
            (*raw).inner = ptr::null_mut();
            (*raw).base.pMethods = ptr::null();
        }
    }
    SQLITE_OK
}

unsafe extern "C" fn x_read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    if buffer.is_null() || amount < 0 || offset < 0 {
        return SQLITE_IOERR_READ;
    }
    let state = locked_file_state!(file, SQLITE_IOERR_READ);
    let target = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), amount as usize) };
    match state.file.seek_read(target, offset as u64) {
        Ok(read) if read == target.len() => SQLITE_OK,
        Ok(read) => {
            target[read..].fill(0);
            SQLITE_IOERR_SHORT_READ
        }
        Err(_) => SQLITE_IOERR_READ,
    }
}

unsafe extern "C" fn x_write(
    file: *mut ffi::sqlite3_file,
    buffer: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    if buffer.is_null() || amount < 0 || offset < 0 {
        return SQLITE_IOERR_WRITE;
    }
    let state = locked_file_state!(file, SQLITE_IOERR_WRITE);
    let source = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), amount as usize) };
    let end = match (offset as u64).checked_add(source.len() as u64) {
        Some(end) => end,
        None => return SQLITE_FULL,
    };
    // An overwrite must not make a pre-existing main/WAL file look smaller in
    // shared quota accounting. Only xTruncate is allowed to reduce a leaf.
    match state
        .state
        .write_with_quota(state.leaf, &state.file, source, offset as u64, end)
    {
        Ok(()) => SQLITE_OK,
        Err(QuotaIoError::Full) => SQLITE_FULL,
        Err(QuotaIoError::Io) => SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn x_truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    if size < 0 {
        return SQLITE_IOERR_TRUNCATE;
    }
    let state = locked_file_state!(file, SQLITE_IOERR_TRUNCATE);
    match state
        .state
        .truncate_with_quota(state.leaf, &state.file, size as u64)
    {
        Ok(()) => SQLITE_OK,
        Err(QuotaIoError::Full) => SQLITE_FULL,
        Err(QuotaIoError::Io) => SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn x_sync(file: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    match locked_file_state!(file, SQLITE_IOERR_FSYNC).file.sync_all() {
        Ok(()) => SQLITE_OK,
        Err(_) => SQLITE_IOERR_FSYNC,
    }
}
unsafe extern "C" fn x_file_size(file: *mut ffi::sqlite3_file, out: *mut i64) -> c_int {
    if out.is_null() {
        return SQLITE_IOERR;
    }
    match locked_file_state!(file, SQLITE_IOERR).file.metadata() {
        Ok(meta) => {
            unsafe {
                *out = meta.len() as i64;
            }
            SQLITE_OK
        }
        Err(_) => SQLITE_IOERR_FSTAT,
    }
}

unsafe extern "C" fn x_lock(file: *mut ffi::sqlite3_file, target: c_int) -> c_int {
    let mut state = locked_file_state!(file, SQLITE_IOERR_LOCK);
    if target <= state.lock_level {
        return SQLITE_OK;
    }
    if target >= ffi::SQLITE_LOCK_SHARED && !state.shared_locked {
        // Match SQLite's Win32 lock protocol: a reader first claims PENDING
        // exclusively, takes its shared byte, then releases PENDING. A writer
        // already transitioning through PENDING therefore blocks new readers.
        let transient_pending = !state.pending_locked;
        if transient_pending {
            match lock_range(&state.file, PENDING_BYTE, 1, true) {
                Ok(true) => state.pending_locked = true,
                Ok(false) => return SQLITE_BUSY,
                Err(_) => return SQLITE_IOERR_LOCK,
            }
        }
        let shared_byte = state.shared_byte;
        match lock_range(&state.file, shared_byte, 1, false) {
            Ok(true) => state.shared_locked = true,
            Ok(false) => {
                if transient_pending {
                    if unlock_range(&state.file, PENDING_BYTE, 1).is_err() {
                        // The kernel may still hold PENDING_BYTE. Keep the
                        // ownership bit until a later xUnlock or xClose can
                        // actually release the exact range.
                        return SQLITE_IOERR_UNLOCK;
                    }
                    state.pending_locked = false;
                }
                return SQLITE_BUSY;
            }
            Err(_) => {
                if transient_pending {
                    if unlock_range(&state.file, PENDING_BYTE, 1).is_err() {
                        // As above, never claim a failed rollback succeeded.
                        return SQLITE_IOERR_UNLOCK;
                    }
                    state.pending_locked = false;
                }
                return SQLITE_IOERR_LOCK;
            }
        }
        if transient_pending {
            if unlock_range(&state.file, PENDING_BYTE, 1).is_err() {
                // Both byte ranges are still owned by this handle unless a
                // later explicit xUnlock succeeds. Do not run a best-effort
                // shared rollback and then manufacture a false lock ledger.
                return SQLITE_IOERR_UNLOCK;
            }
            state.pending_locked = false;
        }
    }
    if target >= ffi::SQLITE_LOCK_RESERVED && !state.reserved_locked {
        match lock_range(&state.file, RESERVED_BYTE, 1, true) {
            Ok(true) => state.reserved_locked = true,
            Ok(false) => return SQLITE_BUSY,
            Err(_) => return SQLITE_IOERR_LOCK,
        }
    }
    if target >= ffi::SQLITE_LOCK_PENDING && !state.pending_locked {
        match lock_range(&state.file, PENDING_BYTE, 1, true) {
            Ok(true) => state.pending_locked = true,
            Ok(false) => return SQLITE_BUSY,
            Err(_) => return SQLITE_IOERR_LOCK,
        }
    }
    if target == ffi::SQLITE_LOCK_EXCLUSIVE && !state.exclusive_locked {
        // The pending byte stops new readers. Release our shared byte before
        // requesting the complete shared range, then restore it if a reader in
        // another process keeps the range busy.
        if state.shared_locked && unlock_range(&state.file, state.shared_byte, 1).is_err() {
            return SQLITE_IOERR_UNLOCK;
        }
        state.shared_locked = false;
        match lock_range(&state.file, SHARED_FIRST, SHARED_SIZE, true) {
            Ok(true) => state.exclusive_locked = true,
            Ok(false) => {
                match lock_range(&state.file, state.shared_byte, 1, false) {
                    Ok(true) => state.shared_locked = true,
                    Ok(false) => return SQLITE_BUSY,
                    Err(_) => return SQLITE_IOERR_LOCK,
                }
                return SQLITE_BUSY;
            }
            Err(_) => return SQLITE_IOERR_LOCK,
        }
    }
    state.lock_level = target;
    SQLITE_OK
}
unsafe extern "C" fn x_unlock(file: *mut ffi::sqlite3_file, target: c_int) -> c_int {
    let mut state = locked_file_state!(file, SQLITE_IOERR_UNLOCK);
    if target != ffi::SQLITE_LOCK_NONE && target != ffi::SQLITE_LOCK_SHARED {
        return SQLITE_IOERR_UNLOCK;
    }
    if target > state.lock_level {
        return SQLITE_IOERR_UNLOCK;
    }
    if state.exclusive_locked && target < ffi::SQLITE_LOCK_EXCLUSIVE {
        if unlock_range(&state.file, SHARED_FIRST, SHARED_SIZE).is_err() {
            return SQLITE_IOERR_UNLOCK;
        }
        state.exclusive_locked = false;
        if target >= ffi::SQLITE_LOCK_SHARED {
            match lock_range(&state.file, state.shared_byte, 1, false) {
                Ok(true) => state.shared_locked = true,
                _ => return SQLITE_IOERR_UNLOCK,
            }
        }
    }
    if state.pending_locked && target < ffi::SQLITE_LOCK_PENDING {
        if unlock_range(&state.file, PENDING_BYTE, 1).is_err() {
            return SQLITE_IOERR_UNLOCK;
        }
        state.pending_locked = false;
    }
    if state.reserved_locked && target < ffi::SQLITE_LOCK_RESERVED {
        if unlock_range(&state.file, RESERVED_BYTE, 1).is_err() {
            return SQLITE_IOERR_UNLOCK;
        }
        state.reserved_locked = false;
    }
    if state.shared_locked && target < ffi::SQLITE_LOCK_SHARED {
        if unlock_range(&state.file, state.shared_byte, 1).is_err() {
            return SQLITE_IOERR_UNLOCK;
        }
        state.shared_locked = false;
    }
    state.lock_level = target;
    SQLITE_OK
}
unsafe extern "C" fn x_check_reserved(file: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    if out.is_null() {
        return SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    let state = locked_file_state!(file, SQLITE_IOERR_CHECKRESERVEDLOCK);
    if state.reserved_locked {
        unsafe {
            *out = 1;
        }
        return SQLITE_OK;
    }
    match lock_range(&state.file, RESERVED_BYTE, 1, true) {
        Ok(true) => {
            let result = unlock_range(&state.file, RESERVED_BYTE, 1);
            unsafe {
                *out = 0;
            }
            if result.is_ok() {
                SQLITE_OK
            } else {
                SQLITE_IOERR_CHECKRESERVEDLOCK
            }
        }
        Ok(false) => {
            unsafe {
                *out = 1;
            }
            SQLITE_OK
        }
        Err(_) => SQLITE_IOERR_CHECKRESERVEDLOCK,
    }
}
unsafe extern "C" fn x_file_control(_: *mut ffi::sqlite3_file, _: c_int, _: *mut c_void) -> c_int {
    SQLITE_NOTFOUND
}
unsafe extern "C" fn x_sector_size(_: *mut ffi::sqlite3_file) -> c_int {
    4096
}
unsafe extern "C" fn x_device_characteristics(_: *mut ffi::sqlite3_file) -> c_int {
    // Every normal Context VFS open withholds FILE_SHARE_DELETE so a live
    // SQLite handle pins its exact leaf against replacement. SQLite must keep
    // a journal handle open accordingly and close it before asking xDelete to
    // acquire the dedicated DELETE-only capability.
    ffi::SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
}

unsafe extern "C" fn x_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    if out.is_null() || page < 0 || page_size <= 0 {
        return SQLITE_IOERR_SHMMAP;
    }
    let mut state = locked_file_state!(file, SQLITE_IOERR_SHMMAP);
    let shm = match state.shm.as_ref() {
        Some(shm) => Arc::clone(shm),
        None => match state.shm_handle() {
            Ok(shm) => {
                state.shm = Some(Arc::clone(&shm));
                shm
            }
            Err(_) => return SQLITE_IOERR_SHMOPEN,
        },
    };
    let mut shm = match shm.lock() {
        Ok(shm) => shm,
        Err(_) => return SQLITE_IOERR_SHMMAP,
    };
    let offset = (page as u64) * (page_size as u64);
    let base = offset / ALLOCATION_GRANULARITY * ALLOCATION_GRANULARITY;
    let in_region = (offset - base) as usize;
    let minimum = in_region + page_size as usize;
    if !shm.maps.contains_key(&base) {
        let required = base + ALLOCATION_GRANULARITY;
        if shm
            .file
            .metadata()
            .map(|m| m.len() < required)
            .unwrap_or(true)
        {
            if extend == 0 {
                unsafe {
                    *out = ptr::null_mut();
                }
                return SQLITE_OK;
            }
            match state
                .state
                .resize_growth_with_quota(ContextLeaf::Shm, &shm.file, required)
            {
                Ok(()) => {}
                Err(QuotaIoError::Full) => return SQLITE_FULL,
                Err(QuotaIoError::Io) => return SQLITE_IOERR_SHMMAP,
            }
        }
        let mapping = unsafe {
            CreateFileMappingW(
                shm.file.as_raw_handle() as HANDLE,
                ptr::null(),
                0x04,
                0,
                0,
                ptr::null(),
            )
        };
        if mapping.is_null() {
            return SQLITE_IOERR_SHMMAP;
        }
        let view = unsafe {
            MapViewOfFile(
                mapping,
                0x0002,
                (base >> 32) as u32,
                base as u32,
                ALLOCATION_GRANULARITY as usize,
            )
        };
        unsafe {
            CloseHandle(mapping);
        }
        if view.is_null() {
            return SQLITE_IOERR_SHMMAP;
        }
        shm.maps.insert(base, view as usize);
    }
    if minimum > ALLOCATION_GRANULARITY as usize {
        return SQLITE_IOERR_SHMMAP;
    }
    unsafe {
        *out = (shm.maps[&base] + in_region) as *mut c_void;
    }
    SQLITE_OK
}
unsafe extern "C" fn x_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    if offset < 0 || count <= 0 {
        return SQLITE_IOERR_SHMLOCK;
    }
    let state = locked_file_state!(file, SQLITE_IOERR_SHMLOCK);
    let Some(shm) = state.shm.as_ref() else {
        return SQLITE_IOERR_SHMLOCK;
    };
    let mut shm = match shm.lock() {
        Ok(shm) => shm,
        Err(_) => return SQLITE_IOERR_SHMLOCK,
    };
    let requested = (
        offset as u64,
        count as u64,
        flags & ffi::SQLITE_SHM_EXCLUSIVE != 0,
    );
    let key = if flags & ffi::SQLITE_SHM_UNLOCK != 0 {
        match shm.locks.iter().find_map(|(&key, owners)| {
            (key.0 == requested.0 && key.1 == requested.1 && owners.contains_key(&state.id))
                .then_some(key)
        }) {
            Some(key) => key,
            None => return SQLITE_IOERR_SHMLOCK,
        }
    } else {
        requested
    };
    let result = if flags & ffi::SQLITE_SHM_UNLOCK != 0 {
        let Some(owners) = shm.locks.get_mut(&key) else {
            return SQLITE_IOERR_SHMLOCK;
        };
        let Some(held) = owners.get_mut(&state.id) else {
            return SQLITE_IOERR_SHMLOCK;
        };
        *held -= 1;
        if *held == 0 {
            owners.remove(&state.id);
        }
        if owners.is_empty() {
            shm.locks.remove(&key);
            unlock_range(&shm.file, key.0, key.1).map(|_| true)
        } else {
            Ok(true)
        }
    } else {
        // A shared/exclusive conflict held in this process must not be sent to
        // UnlockFileEx by another connection. The one kernel range lock is
        // reference-counted here, while LockFileEx covers other processes.
        let conflicting = shm
            .locks
            .iter()
            .any(|(&(start, length, exclusive), owners)| {
                let overlap = start < key.0 + key.1 && key.0 < start + length;
                overlap && !owners.is_empty() && (exclusive || key.2)
            });
        if conflicting {
            Ok(false)
        } else if shm.locks.contains_key(&key) {
            *shm.locks
                .get_mut(&key)
                .unwrap()
                .entry(state.id)
                .or_insert(0) += 1;
            Ok(true)
        } else {
            match lock_range(&shm.file, key.0, key.1, key.2) {
                Ok(true) => {
                    shm.locks.entry(key).or_default().insert(state.id, 1);
                    Ok(true)
                }
                other => other,
            }
        }
    };
    match result {
        Ok(true) => SQLITE_OK,
        Ok(false) => SQLITE_BUSY,
        Err(_) => SQLITE_IOERR_SHMLOCK,
    }
}
unsafe extern "C" fn x_shm_barrier(_: *mut ffi::sqlite3_file) {
    std::sync::atomic::fence(Ordering::SeqCst);
}
unsafe extern "C" fn x_shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    let mut state = locked_file_state!(file, SQLITE_IOERR_SHMOPEN);
    let Some(shm) = state.shm.take() else {
        return SQLITE_OK;
    };
    if delete != 0 && Arc::strong_count(&shm) == 2 {
        let identity = state.state.directory.identity();
        let removed = match state.state.shm.lock() {
            Ok(mut registry) => registry.remove(&identity),
            Err(_) => return SQLITE_IOERR_SHMOPEN,
        };
        // The registry's Arc and the xShmUnmap caller are the last two owners.
        // Drop both before deletion so the no-delete sidecar handle cannot make
        // a successful deletion look like a SQLite error.
        drop(removed);
        drop(shm);
        if state.state.directory.delete_leaf(ContextLeaf::Shm).is_err() {
            return SQLITE_IOERR_SHMOPEN;
        }
        state.state.remove_size(ContextLeaf::Shm);
    }
    SQLITE_OK
}

unsafe extern "C" fn x_delete(vfs: *mut ffi::sqlite3_vfs, name: *const c_char, _: c_int) -> c_int {
    let Some(leaf) = sqlite_name(name) else {
        return SQLITE_CANTOPEN;
    };
    if leaf == ContextLeaf::Main {
        return SQLITE_IOERR;
    }
    let state = unsafe { vfs_state(vfs) };
    let result = state.directory.delete_leaf(leaf);
    #[cfg(test)]
    if let Err(error) = &result {
        // Keep the next native regression bounded and non-sensitive: SQLite
        // already reports the callback result, while this records only the
        // fixed sidecar kind and the underlying native error stage/code.
        // `eprintln!` panics if the test process's stderr is unavailable.
        // This runs in SQLite's C callback, so deliberately discard a failed
        // diagnostic write instead of ever unwinding across the FFI boundary.
        let mut stderr = std::io::stderr();
        let _ = std::io::Write::write_fmt(
            &mut stderr,
            format_args!(
                "Context VFS xDelete leaf={} failed: {error} (kind={:?}, raw_os_error={:?})\n",
                leaf.name(),
                error.kind(),
                error.raw_os_error(),
            ),
        );
    }
    match result {
        Ok(()) => {
            state.remove_size(leaf);
            SQLITE_OK
        }
        // Keep SQLite's normal Windows VFS distinction. A delete-vs-external
        // removal race is not silently accepted, but it is surfaced as the
        // actionable DELETE_NOENT extended IO error rather than an opaque
        // primary SQLITE_IOERR.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            state.remove_size(leaf);
            SQLITE_IOERR_DELETE_NOENT
        }
        Err(_) => SQLITE_IOERR_DELETE,
    }
}
unsafe extern "C" fn x_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    _: c_int,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return SQLITE_IOERR;
    }
    let Some(leaf) = sqlite_name(name) else {
        unsafe {
            *out = 0;
        }
        return SQLITE_OK;
    };
    let state = unsafe { vfs_state(vfs) };
    match state.directory.open_leaf(leaf, false, false) {
        Ok(_) => {
            unsafe {
                *out = 1;
            }
            SQLITE_OK
        }
        Err(_) => {
            unsafe {
                *out = 0;
            }
            SQLITE_OK
        }
    }
}
unsafe extern "C" fn x_full_pathname(
    _: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    out_len: c_int,
    out: *mut c_char,
) -> c_int {
    let Some(leaf) = sqlite_name(name) else {
        return SQLITE_CANTOPEN;
    };
    let bytes = leaf.name().as_bytes();
    if out.is_null() || out_len <= bytes.len() as c_int {
        return SQLITE_CANTOPEN;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr().cast(), out, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    SQLITE_OK
}

unsafe extern "C" fn x_randomness(
    _: *mut ffi::sqlite3_vfs,
    amount: c_int,
    out: *mut c_char,
) -> c_int {
    if amount <= 0 || out.is_null() {
        return 0;
    }
    // BCryptGenRandom with the system-preferred RNG is the Windows CSPRNG.
    // SQLite receives no deterministic fallback for internal random state.
    let amount = amount as u32;
    let status = unsafe { BCryptGenRandom(ptr::null_mut(), out.cast::<u8>(), amount, 0x0000_0002) };
    if status >= 0 { amount as c_int } else { 0 }
}

unsafe extern "C" fn x_sleep(_: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    if microseconds <= 0 {
        return 0;
    }
    // SQLite's contract requires a positive call to sleep for at least the
    // requested interval and return that interval in microseconds.
    let slept = microseconds as u64;
    std::thread::sleep(Duration::from_micros(slept));
    slept as c_int
}

unsafe extern "C" fn x_current_time(_: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    if out.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let Some(millis) = unix_millis() else {
        return ffi::SQLITE_ERROR;
    };
    // Unix epoch is Julian day 2440587.5. The constant below is the same value
    // in milliseconds and avoids a lossy conversion before the final f64.
    unsafe {
        *out = (210_866_760_000_000_i64.saturating_add(millis)) as f64 / 86_400_000.0;
    }
    SQLITE_OK
}

unsafe extern "C" fn x_current_time_int64(_: *mut ffi::sqlite3_vfs, out: *mut i64) -> c_int {
    if out.is_null() {
        return ffi::SQLITE_ERROR;
    }
    let Some(millis) = unix_millis() else {
        return ffi::SQLITE_ERROR;
    };
    unsafe {
        *out = 210_866_760_000_000_i64.saturating_add(millis);
    }
    SQLITE_OK
}

fn unix_millis() -> Option<i64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_millis()).ok()
}

impl VfsState {
    fn reserve(&self, leaf: ContextLeaf, candidate: u64) -> std::io::Result<u64> {
        let mut sizes = self
            .sizes
            .lock()
            .map_err(|_| std::io::Error::other("context quota lock poisoned"))?;
        let current = *sizes.get(&leaf).unwrap_or(&0);
        let total = sizes
            .values()
            .copied()
            .sum::<u64>()
            .saturating_sub(current)
            .saturating_add(candidate);
        if total > self.max_bytes {
            return Err(std::io::Error::from_raw_os_error(112));
        }
        sizes.insert(leaf, candidate);
        Ok(current)
    }
    fn record_size(&self, leaf: ContextLeaf, size: u64) -> std::io::Result<()> {
        self.reserve(leaf, size)?;
        Ok(())
    }
    fn write_with_quota(
        &self,
        leaf: ContextLeaf,
        file: &File,
        source: &[u8],
        offset: u64,
        observed_end: u64,
    ) -> Result<(), QuotaIoError> {
        let mut sizes = self.sizes.lock().map_err(|_| QuotaIoError::Io)?;
        let current = *sizes.get(&leaf).unwrap_or(&0);
        let physical = file.metadata().map_err(|_| QuotaIoError::Io)?.len();
        let candidate = current.max(physical).max(observed_end);
        self.check_quota_locked(&sizes, leaf, current, candidate)?;
        match file.seek_write(source, offset) {
            Ok(written) if written == source.len() => {
                sizes.insert(leaf, candidate);
                Ok(())
            }
            _ => {
                Self::retain_actual_size(&mut sizes, leaf, current, candidate, file);
                Err(QuotaIoError::Io)
            }
        }
    }
    fn truncate_with_quota(
        &self,
        leaf: ContextLeaf,
        file: &File,
        size: u64,
    ) -> Result<(), QuotaIoError> {
        let mut sizes = self.sizes.lock().map_err(|_| QuotaIoError::Io)?;
        let current = *sizes.get(&leaf).unwrap_or(&0);
        self.check_quota_locked(&sizes, leaf, current, size)?;
        match file.set_len(size) {
            Ok(()) => {
                sizes.insert(leaf, size);
                Ok(())
            }
            Err(_) => {
                Self::retain_actual_size(&mut sizes, leaf, current, current, file);
                Err(QuotaIoError::Io)
            }
        }
    }
    fn resize_growth_with_quota(
        &self,
        leaf: ContextLeaf,
        file: &File,
        required: u64,
    ) -> Result<(), QuotaIoError> {
        let mut sizes = self.sizes.lock().map_err(|_| QuotaIoError::Io)?;
        let current = *sizes.get(&leaf).unwrap_or(&0);
        let candidate = current
            .max(file.metadata().map_err(|_| QuotaIoError::Io)?.len())
            .max(required);
        self.check_quota_locked(&sizes, leaf, current, candidate)?;
        match file.set_len(candidate) {
            Ok(()) => {
                sizes.insert(leaf, candidate);
                Ok(())
            }
            Err(_) => {
                Self::retain_actual_size(&mut sizes, leaf, current, candidate, file);
                Err(QuotaIoError::Io)
            }
        }
    }
    fn check_quota_locked(
        &self,
        sizes: &BTreeMap<ContextLeaf, u64>,
        _leaf: ContextLeaf,
        current: u64,
        candidate: u64,
    ) -> Result<(), QuotaIoError> {
        let total = sizes
            .values()
            .copied()
            .sum::<u64>()
            .saturating_sub(current)
            .saturating_add(candidate);
        if total > self.max_bytes {
            Err(QuotaIoError::Full)
        } else {
            Ok(())
        }
    }
    fn retain_actual_size(
        sizes: &mut BTreeMap<ContextLeaf, u64>,
        leaf: ContextLeaf,
        current: u64,
        uncertain_upper_bound: u64,
        file: &File,
    ) {
        let actual = file
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or(uncertain_upper_bound);
        sizes.insert(leaf, current.max(actual).max(uncertain_upper_bound));
    }
    fn remove_size(&self, leaf: ContextLeaf) {
        if let Ok(mut sizes) = self.sizes.lock() {
            sizes.remove(&leaf);
        }
    }
}
impl FileState {
    fn shm_handle(&self) -> std::io::Result<Arc<Mutex<SharedMemory>>> {
        let identity = self.state.directory.identity();
        let mut registry = self
            .state
            .shm
            .lock()
            .map_err(|_| std::io::Error::other("context SHM registry poisoned"))?;
        if let Some(existing) = registry.get(&identity) {
            return Ok(Arc::clone(existing));
        }
        let file = self
            .state
            .directory
            .open_leaf(ContextLeaf::Shm, true, true)?;
        let existing_size = file.metadata()?.len();
        // A reopened database can already have a large -shm sidecar. Account
        // for it before mapping any page so restart cannot bypass max_bytes.
        self.state.record_size(ContextLeaf::Shm, existing_size)?;
        let shared = Arc::new(Mutex::new(SharedMemory {
            file,
            maps: BTreeMap::new(),
            locks: BTreeMap::new(),
        }));
        registry.insert(identity, Arc::clone(&shared));
        Ok(shared)
    }
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: isize,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LockFileEx(
        file: HANDLE,
        flags: u32,
        reserved: u32,
        low: u32,
        high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn UnlockFileEx(
        file: HANDLE,
        reserved: u32,
        low: u32,
        high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn CreateFileMappingW(
        file: HANDLE,
        attributes: *const c_void,
        protect: u32,
        maximum_size_high: u32,
        maximum_size_low: u32,
        name: *const u16,
    ) -> HANDLE;
    fn MapViewOfFile(
        mapping: HANDLE,
        access: u32,
        offset_high: u32,
        offset_low: u32,
        bytes: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(address: *const c_void) -> i32;
    fn CloseHandle(handle: HANDLE) -> i32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, length: u32, flags: u32) -> i32;
}
fn overlapped(offset: u64) -> Overlapped {
    Overlapped {
        internal: 0,
        internal_high: 0,
        offset: offset as u32,
        offset_high: (offset >> 32) as u32,
        event: 0,
    }
}
fn lock_range(file: &File, offset: u64, len: u64, exclusive: bool) -> std::io::Result<bool> {
    let mut ov = overlapped(offset);
    let flags = LOCKFILE_FAIL_IMMEDIATELY
        | if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            0
        };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            flags,
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    } != 0;
    if ok {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == 33 {
        Ok(false)
    } else {
        Err(std::io::Error::from_raw_os_error(error as i32))
    }
}
fn unlock_range(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
    #[cfg(test)]
    if TEST_FAIL_NEXT_UNLOCK.with(|failure| {
        if failure.get() == Some((offset, len)) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(std::io::Error::other("injected Context VFS unlock failure"));
    }
    let mut ov = overlapped(offset);
    if unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    } != 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(test, windows))]
mod native_acceptance {
    use super::*;
    use std::{
        fs::{self, File},
        os::windows::fs::symlink_file,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{Connection, ErrorCode, OpenFlags, params};

    static NEXT_FIXTURE_ROOT: AtomicU64 = AtomicU64::new(1);
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    struct NativeFixture {
        root: PathBuf,
        vfs: ContextStoreVfs,
    }

    impl NativeFixture {
        fn new() -> Self {
            let root = fixture_root_path();
            if !root.exists() {
                crate::wal::win_native::create_private_directory_new(&root)
                    .expect("create a TokenUser-private native VFS fixture directory");
            }
            // A normal `OpenOptions` directory open is not a Windows
            // directory capability: it lacks the no-follow directory flags
            // needed by the production component walk. Reuse that exact
            // boundary so this test exercises the VFS instead of failing
            // before it exists with ERROR_ACCESS_DENIED.
            let bound = crate::skills::store::open_absolute_bound_directory(
                &root,
                false,
                "native Context VFS test root",
            )
            .expect("walk the native VFS fixture root as a no-follow capability")
            .expect("native VFS fixture root exists");
            let directory = PinnedContextDirectory::duplicate_verified_handle(&bound.dir)
                .expect("fixture directory passes handle-bound private-DACL proof");
            let vfs = ContextStoreVfs::register(directory, 2 * 1024 * 1024)
                .expect("register one bounded native Context VFS root");
            Self { root, vfs }
        }

        fn open(&self) -> Connection {
            Connection::open_with_flags_and_vfs(
                "context.db",
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
                self.vfs.name(),
            )
            .expect("open context database through the native VFS")
        }
    }

    fn fixture_root_path() -> PathBuf {
        std::env::var_os("NEOTH_CONTEXT_VFS_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "neoth-context-vfs-native-{}-{}",
                    std::process::id(),
                    NEXT_FIXTURE_ROOT.fetch_add(1, Ordering::Relaxed)
                ))
            })
    }

    fn fixture_footprint_total(fixture: &NativeFixture) -> u64 {
        let (_, database, wal, shm) = fixture
            .vfs
            .footprint()
            .expect("read capability-bound native VFS fixture footprint");
        database
            .checked_add(wal)
            .and_then(|total| total.checked_add(shm))
            .expect("native VFS fixture footprint fits u64")
    }

    #[test]
    fn vfs_version_one_callbacks_are_usable_and_failed_open_clears_methods() {
        let mut random = [0_u8; 32];
        assert_eq!(
            unsafe {
                x_randomness(
                    ptr::null_mut(),
                    random.len() as c_int,
                    random.as_mut_ptr().cast(),
                )
            },
            random.len() as c_int
        );
        assert_eq!(unsafe { x_sleep(ptr::null_mut(), 0) }, 0);
        let mut julian = 0_f64;
        let mut julian_millis = 0_i64;
        assert_eq!(
            unsafe { x_current_time(ptr::null_mut(), &mut julian) },
            SQLITE_OK
        );
        assert_eq!(
            unsafe { x_current_time_int64(ptr::null_mut(), &mut julian_millis) },
            SQLITE_OK
        );
        assert!(
            (julian * 86_400_000.0 - julian_millis as f64).abs() < 2.0,
            "both SQLite time callbacks use the same Julian UTC epoch"
        );
        assert_ne!(
            unsafe { x_device_characteristics(ptr::null_mut()) }
                & ffi::SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN,
            0,
            "ordinary Context VFS handles deny delete sharing, so SQLite must close a sidecar before xDelete"
        );

        let mut file = ffi::sqlite3_file {
            pMethods: &IO_METHODS,
        };
        assert_eq!(
            unsafe { x_open(ptr::null_mut(), ptr::null(), &mut file, 0, ptr::null_mut()) },
            SQLITE_CANTOPEN
        );
        assert!(
            file.pMethods.is_null(),
            "failed xOpen must never leave stale methods in SQLite storage"
        );
    }

    #[test]
    fn schema_wal_checkpoint_and_reopen_preserve_a_committed_row() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let mut first = fixture.open();
        first.execute_batch(
            "PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL;\
             CREATE TABLE IF NOT EXISTS native_vfs_commit (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
        ).unwrap();
        let tx = first.transaction().unwrap();
        tx.execute(
            "INSERT INTO native_vfs_commit(value) VALUES (?1)",
            ["committed"],
        )
        .unwrap();
        tx.commit().unwrap();
        first
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        drop(first);

        let reopened = fixture.open();
        let value: String = reopened
            .query_row(
                "SELECT value FROM native_vfs_commit ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "committed");
    }

    #[test]
    fn two_connections_use_wal_shm_and_observe_sqlite_locking() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let writer = fixture.open();
        writer.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS native_vfs_locks (value INTEGER);").unwrap();
        let reader = fixture.open();
        writer
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO native_vfs_locks VALUES (1);")
            .unwrap();
        let visible: i64 = reader
            .query_row("SELECT COUNT(*) FROM native_vfs_locks", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            visible >= 0,
            "reader remains usable while writer owns a WAL lock"
        );
        let second_writer =
            reader.execute_batch("BEGIN IMMEDIATE; INSERT INTO native_vfs_locks VALUES (2);");
        assert!(
            second_writer.is_err(),
            "SQLite must surface a competing writer lock"
        );
        writer
            .execute_batch("COMMIT; PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        reader
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO native_vfs_locks VALUES (3); COMMIT;")
            .unwrap();
    }

    #[test]
    fn pending_writer_blocks_a_new_reader_before_the_shared_byte_is_taken() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let bootstrap = fixture.open();
        bootstrap.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS native_vfs_pending_guard (value INTEGER);").unwrap();
        drop(bootstrap);
        let pending = fixture
            .vfs
            .state
            .directory
            .open_leaf(ContextLeaf::Main, true, false)
            .unwrap();
        assert!(
            lock_range(&pending, PENDING_BYTE, 1, true).unwrap(),
            "fixture must hold SQLite PENDING_BYTE as an existing writer"
        );
        let reader = fixture.open();
        let read = reader.query_row("SELECT COUNT(*) FROM native_vfs_pending_guard", [], |row| {
            row.get::<_, i64>(0)
        });
        assert!(
            read.is_err(),
            "a reader must not bypass a live pending writer while acquiring SQLITE_LOCK_SHARED"
        );
        unlock_range(&pending, PENDING_BYTE, 1).unwrap();
        let recovered: i64 = reader
            .query_row("SELECT COUNT(*) FROM native_vfs_pending_guard", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            recovered >= 0,
            "reader reacquires shared access after the pending writer releases it"
        );
    }

    #[test]
    fn failed_transient_pending_unlock_retains_lock_ownership_until_retry() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let bootstrap = fixture.open();
        bootstrap
            .execute_batch(
                "PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS native_vfs_unlock_guard (value INTEGER);",
            )
            .unwrap();
        drop(bootstrap);

        let file = fixture
            .vfs
            .state
            .directory
            .open_leaf(ContextLeaf::Main, true, false)
            .unwrap();
        let raw = Box::into_raw(Box::new(ContextFile {
            base: ffi::sqlite3_file {
                pMethods: &IO_METHODS,
            },
            inner: Box::into_raw(Box::new(Mutex::new(FileState {
                file,
                leaf: ContextLeaf::Main,
                state: fixture.vfs.state,
                lock_level: ffi::SQLITE_LOCK_NONE,
                shared_byte: SHARED_FIRST,
                shared_locked: false,
                reserved_locked: false,
                pending_locked: false,
                exclusive_locked: false,
                id: NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed),
                shm: None,
            }))),
        }));

        fail_next_unlock_for_test(PENDING_BYTE, 1);
        assert_eq!(
            unsafe { x_lock(raw.cast(), ffi::SQLITE_LOCK_SHARED) },
            SQLITE_IOERR_UNLOCK,
            "a failed transient PENDING release is an SQLite unlock error"
        );
        let state = unsafe { (&*(*raw).inner).lock().unwrap() };
        assert!(
            state.pending_locked && state.shared_locked,
            "the ledger retains every kernel range whose release did not succeed"
        );
        drop(state);

        assert_eq!(
            unsafe { x_unlock(raw.cast(), ffi::SQLITE_LOCK_NONE) },
            SQLITE_OK,
            "a later explicit unlock releases the conservatively retained ranges"
        );
        let state = unsafe { (&*(*raw).inner).lock().unwrap() };
        assert!(
            !state.pending_locked && !state.shared_locked,
            "successful retry is the only operation that clears lock ownership"
        );
        drop(state);
        assert_eq!(unsafe { x_close(raw.cast()) }, SQLITE_OK);
    }

    #[test]
    fn attaching_a_preexisting_large_shm_file_consumes_restart_quota() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let bootstrap = fixture.open();
        bootstrap.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS native_vfs_existing_shm (value INTEGER);").unwrap();
        drop(bootstrap);
        let sidecar = fixture
            .vfs
            .state
            .directory
            .open_leaf(ContextLeaf::Shm, true, true)
            .unwrap();
        sidecar.set_len(1_900_000).unwrap();
        // Simulate a new process: discard only this test process's registry and
        // ledger, then attach the existing on-disk SHM object through the VFS.
        fixture.vfs.state.shm.lock().unwrap().clear();
        fixture.vfs.state.remove_size(ContextLeaf::Shm);
        let main = fixture
            .vfs
            .state
            .directory
            .open_leaf(ContextLeaf::Main, true, false)
            .unwrap();
        let file_state = FileState {
            file: main,
            leaf: ContextLeaf::Main,
            state: fixture.vfs.state,
            lock_level: ffi::SQLITE_LOCK_NONE,
            shared_byte: SHARED_FIRST,
            shared_locked: false,
            reserved_locked: false,
            pending_locked: false,
            exclusive_locked: false,
            id: NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed),
            shm: None,
        };
        let attached = file_state.shm_handle().unwrap();
        assert!(
            fixture
                .vfs
                .state
                .reserve(ContextLeaf::Journal, 200_000)
                .is_err(),
            "restart accounting includes pre-existing SHM before later sidecar growth"
        );
        drop(attached);
        drop(file_state);
        fixture.vfs.state.shm.lock().unwrap().clear();
        sidecar.set_len(0).unwrap();
        fixture.vfs.state.remove_size(ContextLeaf::Shm);
    }

    #[test]
    fn extending_write_returns_sqlite_full_without_an_ambient_fallback() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let connection = fixture.open();
        connection.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA journal_mode=DELETE; CREATE TABLE native_vfs_quota (payload BLOB);").unwrap();
        let result = connection.execute(
            "INSERT INTO native_vfs_quota(payload) VALUES (?1)",
            params![vec![0_u8; 3 * 1024 * 1024]],
        );
        assert!(
            matches!(
                result,
                Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::DiskFull
            ),
            "the VFS quota must report SQLite FULL for an extending rollback-journal write"
        );
        connection
            .execute("INSERT INTO native_vfs_quota(payload) VALUES (X'01')", [])
            .expect("a rejected rollback-journal write leaves reusable quota");
        connection
            .query_row("SELECT COUNT(*) FROM native_vfs_quota", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| assert_eq!(count, 1))
            .unwrap();
    }

    #[test]
    fn failed_wal_write_preserves_committed_data_and_recovers_quota_on_reopen() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let connection = fixture.open();
        connection
            .execute_batch(
                "PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL;\
             CREATE TABLE native_vfs_wal_quota (kind TEXT PRIMARY KEY, payload BLOB NOT NULL);\
             INSERT INTO native_vfs_wal_quota(kind, payload) VALUES ('sentinel', X'01');",
            )
            .expect("commit the WAL sentinel before exhausting quota");
        let (busy, log_pages, checkpointed_pages): (i64, i64, i64) = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("checkpoint the committed WAL sentinel before exhausting quota");
        assert_eq!(busy, 0, "baseline WAL checkpoint cannot remain blocked");
        assert_eq!(
            log_pages, checkpointed_pages,
            "baseline WAL checkpoint must complete every WAL frame it reports"
        );
        assert!(
            fixture_footprint_total(&fixture) <= 2 * 1024 * 1024,
            "the committed sentinel starts within the VFS physical quota"
        );
        let result = connection.execute(
            "INSERT INTO native_vfs_wal_quota(kind, payload) VALUES ('oversized', ?1)",
            params![vec![0_u8; 3 * 1024 * 1024]],
        );
        assert!(
            matches!(
                result,
                Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::DiskFull
            ),
            "the VFS quota must report SQLite FULL for an extending WAL write"
        );
        assert!(
            fixture_footprint_total(&fixture) <= 2 * 1024 * 1024,
            "a rejected WAL write cannot exceed the VFS physical quota"
        );
        drop(connection);

        let reopened = fixture.open();
        let (busy, log_pages, checkpointed_pages): (i64, i64, i64) = reopened
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("an uncommitted WAL tail must not prevent bounded recovery");
        assert_eq!(busy, 0, "recovery checkpoint cannot remain blocked");
        assert_eq!(
            log_pages, checkpointed_pages,
            "recovery checkpoint must complete every WAL frame it reports"
        );
        assert!(
            fixture_footprint_total(&fixture) <= 2 * 1024 * 1024,
            "recovery checkpoint preserves the VFS physical quota"
        );
        let sentinel: Vec<u8> = reopened
            .query_row(
                "SELECT payload FROM native_vfs_wal_quota WHERE kind='sentinel'",
                [],
                |row| row.get(0),
            )
            .expect("checkpoint recovery preserves committed data");
        assert_eq!(sentinel, vec![1]);
        reopened
            .execute(
                "INSERT INTO native_vfs_wal_quota(kind, payload) VALUES ('reused', X'02')",
                [],
            )
            .expect("recovered WAL quota permits a later small write");
    }

    #[test]
    fn in_place_overwrite_cannot_free_quota_for_later_main_or_sidecar_growth() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let connection = fixture.open();
        connection.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS native_vfs_overwrite_quota (id INTEGER PRIMARY KEY, payload BLOB);").unwrap();
        connection
            .execute(
                "INSERT INTO native_vfs_overwrite_quota(payload) VALUES (zeroblob(?1))",
                [700_000_i64],
            )
            .unwrap();
        // This dirties an existing early database page. The raw xWrite is a
        // small overwrite, but the physical main file remains about 700 KiB.
        connection.execute("UPDATE native_vfs_overwrite_quota SET payload = X'01' || substr(payload, 2) WHERE id = 1", []).unwrap();
        let result = connection.execute(
            "INSERT INTO native_vfs_overwrite_quota(payload) VALUES (zeroblob(?1))",
            [1_700_000_i64],
        );
        assert!(
            result.is_err(),
            "an overwrite must not create fictitious quota headroom for main or journal growth"
        );
    }

    #[test]
    fn aliases_and_non_allowlisted_sidecars_cannot_be_opened() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let rejected = Connection::open_with_flags_and_vfs(
            ".\\context.db",
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            fixture.vfs.name(),
        );
        assert!(
            rejected.is_err(),
            "component aliases must not reach the pinned directory"
        );
        let rejected = Connection::open_with_flags_and_vfs(
            "context.db:stream",
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            fixture.vfs.name(),
        );
        assert!(
            rejected.is_err(),
            "ADS syntax must not reach the pinned directory"
        );
    }

    #[test]
    fn replacement_reparse_and_inherited_child_dacl_are_rejected_on_the_opened_handle() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let connection = fixture.open();
        connection
            .execute_batch("CREATE TABLE IF NOT EXISTS native_vfs_swap_guard (value INTEGER);")
            .unwrap();
        let root = &fixture.root;
        let main = root.join(ContextLeaf::Main.name());
        assert!(
            fs::remove_file(&main).is_err(),
            "the live main capability denies replacement sharing"
        );
        drop(connection);

        let journal = root.join(ContextLeaf::Journal.name());
        let _ = fs::remove_file(&journal);
        File::create(&journal).unwrap();
        assert!(
            fixture
                .vfs
                .state
                .directory
                .open_leaf(ContextLeaf::Journal, true, false)
                .is_err(),
            "a child inheriting an unprotected DACL is not accepted as a context sidecar"
        );
        fs::remove_file(&journal).unwrap();

        let attacker = root.join("attacker-controlled.db");
        File::create(&attacker).unwrap();
        symlink_file(&attacker, &journal)
            .expect("native acceptance host permits file reparse fixture creation");
        assert!(
            fixture
                .vfs
                .state
                .directory
                .open_leaf(ContextLeaf::Journal, true, true)
                .is_err(),
            "the relative NT open must reject a reparse leaf before SQLite can use it"
        );
        fs::remove_file(&journal).unwrap();
        fs::remove_file(&attacker).unwrap();
    }

    #[test]
    fn crash_writer_worker_commits_then_terminates_without_close() {
        if std::env::var_os("NEOTH_CONTEXT_VFS_CRASH_WORKER").is_none() {
            return;
        }
        let fixture = NativeFixture::new();
        let connection = fixture.open();
        connection.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS native_vfs_crash (value TEXT);").unwrap();
        connection
            .execute(
                "INSERT INTO native_vfs_crash(value) VALUES ('durable-before-abort')",
                [],
            )
            .unwrap();
        // sync WAL through the raw xSync callback before process termination.
        connection
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
            .unwrap();
        std::process::abort();
    }

    #[test]
    fn abrupt_writer_termination_recovers_committed_wal_data_on_reopen() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let fixture = NativeFixture::new();
        let root = &fixture.root;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "context_graph::windows_vfs::native_acceptance::crash_writer_worker_commits_then_terminates_without_close", "--nocapture"])
            .env("NEOTH_CONTEXT_VFS_CRASH_WORKER", "1")
            .env("NEOTH_CONTEXT_VFS_TEST_ROOT", root)
            .status().expect("launch isolated native SQLite crash writer");
        assert!(
            !status.success(),
            "crash fixture must terminate before SQLite close callbacks"
        );
        let reopened = fixture.open();
        let value: String = reopened
            .query_row(
                "SELECT value FROM native_vfs_crash ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "durable-before-abort");
    }
}
