//! Obsidian vault-sync robustness helpers (GOLD-ADAPT-IGNIS-01/02/03).
//!
//! Three small, independently unit-testable primitives:
//!
//! * [`WriteCoalescer`] — IGNIS-01: batch pending (path, bytes) writes, skip
//!   files whose disk content is byte-identical to the pending bytes.
//! * [`DirMtimeCache`] — IGNIS-02: per-directory mtime cache; skip tree-walk
//!   for directories whose mtime has not changed since the last check.
//! * [`EchoGuard`] — IGNIS-03: ring-buffer guard that tracks recently-written
//!   (path, content-hash) pairs so a future reverse-sync watcher can ignore
//!   changes NEOTH itself produced (avoids feedback loops).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Shared hasher — reuses the same xxh3_64 already used in obsidian.rs.
// ---------------------------------------------------------------------------

fn xxh3(bytes: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(bytes)
}

// ---------------------------------------------------------------------------
// IGNIS-01 — WriteCoalescer
// ---------------------------------------------------------------------------

/// A pending (destination path, raw bytes) write entry.
struct PendingWrite {
    dst: PathBuf,
    bytes: Vec<u8>,
}

/// Collects writes and flushes them in one pass, skipping files whose on-disk
/// content is already byte-identical to what would be written.
///
/// This avoids churning the vault's metadata on every sync tick when nothing
/// has actually changed, which matters most on network-mounted (e.g. NAS /
/// cloud-backed) vaults where each `write(2)` is a network round-trip.
///
/// # Usage
/// ```ignore
/// let mut coalescer = WriteCoalescer::new();
/// coalescer.push(dst_path, bytes);
/// let (written, skipped) = coalescer.flush()?;
/// ```
#[derive(Default)]
pub struct WriteCoalescer {
    pending: Vec<PendingWrite>,
}

impl WriteCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a write.  The caller owns the destination path construction;
    /// the coalescer only decides whether to skip or commit each entry.
    pub fn push(&mut self, dst: PathBuf, bytes: Vec<u8>) {
        self.pending.push(PendingWrite { dst, bytes });
    }

    /// Flush all pending writes.
    ///
    /// For each entry:
    /// 1. Read the on-disk file (if it exists) and hash it.
    /// 2. If the hash matches the pending bytes, skip (no write, no mtime
    ///    bump).
    /// 3. Otherwise write atomically via a `.tmp` sibling + rename.
    ///
    /// Returns `(written, skipped_identical)`.
    pub fn flush(self) -> Result<(usize, usize)> {
        let mut written = 0usize;
        let mut skipped = 0usize;

        for PendingWrite { dst, bytes } in self.pending {
            // Check byte-identity before touching disk.
            if dst.exists() {
                match std::fs::read(&dst) {
                    Ok(existing) if xxh3(&existing) == xxh3(&bytes) => {
                        skipped += 1;
                        continue;
                    }
                    _ => {} // missing, unreadable, or different — fall through
                }
            }

            // Create parent dir if needed.
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create dir {}", parent.display()))?;
            }

            // Atomic write: write to .tmp then rename.
            let tmp = dst.with_extension("coalesce.tmp");
            std::fs::write(&tmp, &bytes)
                .with_context(|| format!("write tmp {}", tmp.display()))?;
            std::fs::rename(&tmp, &dst)
                .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))?;
            written += 1;
        }

        Ok((written, skipped))
    }
}

// ---------------------------------------------------------------------------
// IGNIS-02 — DirMtimeCache
// ---------------------------------------------------------------------------

/// Caches the last-observed mtime of directories.  On each `is_changed` call
/// the directory's current mtime is read; if it matches the cached value the
/// directory is considered unchanged and the caller can skip the tree-walk.
///
/// The cache auto-updates: a `true` return means "changed (or first call)";
/// a `false` return means "identical mtime since last check".
///
/// # Thread-safety
/// Single-threaded / `&mut self` API; wrap in `Mutex` if sharing across
/// async tasks.
#[derive(Default)]
pub struct DirMtimeCache {
    cache: HashMap<PathBuf, SystemTime>,
}

impl DirMtimeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the directory's mtime has changed since the last call
    /// (or if this is the first call for this path), `false` otherwise.
    ///
    /// If the directory does not exist or its mtime cannot be read, returns
    /// `true` so the caller falls back to a full walk.
    pub fn is_changed(&mut self, dir: &Path) -> bool {
        let mtime = match dir.metadata().and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => return true, // non-existent or permission error → assume changed
        };

        match self.cache.get(dir) {
            Some(&cached) if cached == mtime => false,
            _ => {
                self.cache.insert(dir.to_path_buf(), mtime);
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IGNIS-03 — EchoGuard
// ---------------------------------------------------------------------------

/// Default TTL for echo entries: 30 seconds.  Short enough that operator edits
/// made after a sync are not silently suppressed; long enough to outlive any
/// reasonable file-watcher debounce window.
pub const ECHO_GUARD_DEFAULT_TTL: Duration = Duration::from_secs(30);

/// Maximum number of entries kept in the ring.  Oldest are evicted when the
/// ring is full.
const ECHO_RING_CAP: usize = 256;

struct EchoEntry {
    path: PathBuf,
    content_hash: u64,
    written_at: Instant,
}

/// Tracks recently-written (path, content-hash) pairs so a future
/// reverse-sync watcher can distinguish NEOTH's own writes from genuine
/// operator edits and avoid infinite sync feedback loops.
///
/// # Usage
/// ```ignore
/// let mut guard = EchoGuard::new(ECHO_GUARD_DEFAULT_TTL);
/// guard.register_write(&dst, &bytes);
/// // … later, in the watcher callback …
/// if !guard.is_own_echo(&changed_path, &changed_bytes) {
///     // process as genuine operator edit
/// }
/// ```
pub struct EchoGuard {
    ring: Vec<EchoEntry>,
    ttl: Duration,
}

impl EchoGuard {
    pub fn new(ttl: Duration) -> Self {
        Self { ring: Vec::with_capacity(ECHO_RING_CAP), ttl }
    }

    /// Record that NEOTH just wrote `bytes` to `path`.
    pub fn register_write(&mut self, path: &Path, bytes: &[u8]) {
        // Evict expired entries first to keep the ring compact.
        self.evict_expired();

        // If the ring is full, drop the oldest entry.
        if self.ring.len() >= ECHO_RING_CAP {
            self.ring.remove(0);
        }

        self.ring.push(EchoEntry {
            path: path.to_path_buf(),
            content_hash: xxh3(bytes),
            written_at: Instant::now(),
        });
    }

    /// Returns `true` if the given (path, bytes) pair was recently written by
    /// NEOTH (within the TTL window), meaning a watcher should ignore this
    /// change event.
    pub fn is_own_echo(&mut self, path: &Path, bytes: &[u8]) -> bool {
        self.evict_expired();
        let hash = xxh3(bytes);
        self.ring
            .iter()
            .any(|e| e.path == path && e.content_hash == hash)
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.ring.retain(|e| now.duration_since(e.written_at) < self.ttl);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use tempfile::tempdir;

    // ── IGNIS-01 WriteCoalescer ──────────────────────────────────────────────

    #[test]
    fn coalescer_writes_new_file() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("note.md");
        let mut c = WriteCoalescer::new();
        c.push(dst.clone(), b"# Hello".to_vec());
        let (written, skipped) = c.flush().unwrap();
        assert_eq!(written, 1);
        assert_eq!(skipped, 0);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "# Hello");
    }

    #[test]
    fn coalescer_skips_identical_existing_file() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("note.md");
        std::fs::write(&dst, b"# Hello").unwrap();

        let mut c = WriteCoalescer::new();
        c.push(dst.clone(), b"# Hello".to_vec());
        let (written, skipped) = c.flush().unwrap();
        assert_eq!(written, 0);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn coalescer_rewrites_changed_file() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("note.md");
        std::fs::write(&dst, b"# Old").unwrap();

        let mut c = WriteCoalescer::new();
        c.push(dst.clone(), b"# New".to_vec());
        let (written, skipped) = c.flush().unwrap();
        assert_eq!(written, 1);
        assert_eq!(skipped, 0);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "# New");
    }

    #[test]
    fn coalescer_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("deep/sub/dir/note.md");
        let mut c = WriteCoalescer::new();
        c.push(dst.clone(), b"content".to_vec());
        let (written, _) = c.flush().unwrap();
        assert_eq!(written, 1);
        assert!(dst.exists());
    }

    #[test]
    fn coalescer_handles_multiple_entries_mixed() {
        let dir = tempdir().unwrap();
        let same = dir.path().join("same.md");
        let diff = dir.path().join("diff.md");
        std::fs::write(&same, b"unchanged").unwrap();
        std::fs::write(&diff, b"old").unwrap();

        let mut c = WriteCoalescer::new();
        c.push(same.clone(), b"unchanged".to_vec());
        c.push(diff.clone(), b"new".to_vec());
        let (written, skipped) = c.flush().unwrap();
        assert_eq!(written, 1);
        assert_eq!(skipped, 1);
    }

    // ── IGNIS-02 DirMtimeCache ───────────────────────────────────────────────

    #[test]
    fn dir_mtime_cache_first_call_is_changed() {
        let dir = tempdir().unwrap();
        let mut cache = DirMtimeCache::new();
        assert!(cache.is_changed(dir.path()), "first call must return true");
    }

    #[test]
    fn dir_mtime_cache_second_call_unchanged() {
        let dir = tempdir().unwrap();
        let mut cache = DirMtimeCache::new();
        cache.is_changed(dir.path()); // prime the cache
        assert!(
            !cache.is_changed(dir.path()),
            "second call with no FS change must return false"
        );
    }

    #[test]
    fn dir_mtime_cache_detects_change_after_write() {
        let dir = tempdir().unwrap();
        let mut cache = DirMtimeCache::new();
        cache.is_changed(dir.path()); // prime

        // Sleep briefly so mtime granularity (1 s on most FS) advances.
        // We write a file — the directory's mtime updates on most platforms.
        sleep(Duration::from_millis(1100));
        std::fs::write(dir.path().join("new.md"), b"x").unwrap();

        assert!(
            cache.is_changed(dir.path()),
            "mtime must change after a file is added to the directory"
        );
    }

    #[test]
    fn dir_mtime_cache_nonexistent_returns_true() {
        let mut cache = DirMtimeCache::new();
        let p = PathBuf::from("/nonexistent/path/that/does/not/exist");
        assert!(cache.is_changed(&p), "missing dir must be treated as changed");
    }

    // ── IGNIS-03 EchoGuard ──────────────────────────────────────────────────

    #[test]
    fn echo_guard_detects_own_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("note.md");
        let bytes = b"# session\nhello";

        let mut guard = EchoGuard::new(ECHO_GUARD_DEFAULT_TTL);
        guard.register_write(&path, bytes);
        assert!(
            guard.is_own_echo(&path, bytes),
            "must recognise the path+content we just registered"
        );
    }

    #[test]
    fn echo_guard_different_content_is_not_echo() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("note.md");

        let mut guard = EchoGuard::new(ECHO_GUARD_DEFAULT_TTL);
        guard.register_write(&path, b"original");
        assert!(
            !guard.is_own_echo(&path, b"operator edit"),
            "different content must not match"
        );
    }

    #[test]
    fn echo_guard_unregistered_path_is_not_echo() {
        let dir = tempdir().unwrap();
        let registered = dir.path().join("registered.md");
        let other = dir.path().join("other.md");
        let bytes = b"content";

        let mut guard = EchoGuard::new(ECHO_GUARD_DEFAULT_TTL);
        guard.register_write(&registered, bytes);
        assert!(
            !guard.is_own_echo(&other, bytes),
            "different path must not match even with same content"
        );
    }

    #[test]
    fn echo_guard_expires_after_ttl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("note.md");
        let bytes = b"content";

        let ttl = Duration::from_millis(50);
        let mut guard = EchoGuard::new(ttl);
        guard.register_write(&path, bytes);

        sleep(Duration::from_millis(100));
        assert!(
            !guard.is_own_echo(&path, bytes),
            "entry must expire after TTL"
        );
    }

    #[test]
    fn echo_guard_ring_cap_evicts_oldest() {
        let dir = tempdir().unwrap();
        let bytes = b"x";
        let ttl = Duration::from_secs(60);
        let mut guard = EchoGuard::new(ttl);

        // Fill past cap; the very first entry should be evicted.
        let first_path = dir.path().join("0.md");
        guard.register_write(&first_path, bytes);
        for i in 1..=ECHO_RING_CAP {
            let p = dir.path().join(format!("{i}.md"));
            guard.register_write(&p, bytes);
        }
        assert!(
            !guard.is_own_echo(&first_path, bytes),
            "oldest entry must be evicted when ring is full"
        );
    }
}
