//! Obsidian vault-sync robustness helpers (GOLD-ADAPT-IGNIS-01/02/03/04).
//!
//! Four small, independently unit-testable primitives:
//!
//! * [`WriteCoalescer`] — IGNIS-01: batch pending (path, bytes) writes, skip
//!   files whose disk content is byte-identical to the pending bytes.
//! * [`DirMtimeCache`] — IGNIS-02: per-directory mtime cache; skip tree-walk
//!   for directories whose mtime has not changed since the last check.
//! * [`EchoGuard`] — IGNIS-03: ring-buffer guard that tracks recently-written
//!   (path, content-hash) pairs so a future reverse-sync watcher can ignore
//!   changes NEOTH itself produced (avoids feedback loops).
//! * [`detect_sync_conflicts`] / [`SyncConflictReport`] — IGNIS-04: walk the
//!   vault and detect cloud-sync conflict-marker files left by Syncthing,
//!   Dropbox, iCloud, or similar. [`obsidian_core_sync_enabled`] separately
//!   checks Obsidian's built-in Sync plugin. Call both before writing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};

const CORE_PLUGINS_MAX_BYTES: u64 = 1024 * 1024;

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
            std::fs::write(&tmp, &bytes).with_context(|| format!("write tmp {}", tmp.display()))?;
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
        Self {
            ring: Vec::with_capacity(ECHO_RING_CAP),
            ttl,
        }
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
        self.ring
            .retain(|e| now.duration_since(e.written_at) < self.ttl);
    }
}

// ---------------------------------------------------------------------------
// IGNIS-04 — SyncConflictReport / detect_sync_conflicts
// ---------------------------------------------------------------------------

/// Read `.obsidian/core-plugins.json` and report whether Obsidian's built-in
/// Sync plugin is enabled.
///
/// Obsidian has used both an array of enabled plugin IDs and a boolean object
/// representation over time, so both `["sync"]` and `{ "sync": true }` are
/// accepted. Missing configuration means the plugin is not enabled. An
/// unreadable, oversized, symlinked, or malformed file is an error so callers
/// can fail closed instead of writing while the sync state is unknown.
pub fn obsidian_core_sync_enabled(vault_dir: &Path) -> Result<bool> {
    let path = vault_dir.join(".obsidian").join("core-plugins.json");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("stat {}", path.display()));
        }
    };

    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "{} must be a regular file before Obsidian sync can run",
            path.display()
        );
    }
    if metadata.len() > CORE_PLUGINS_MAX_BYTES {
        anyhow::bail!(
            "{} exceeds the {} byte safety limit",
            path.display(),
            CORE_PLUGINS_MAX_BYTES
        );
    }

    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;

    match value {
        serde_json::Value::Object(entries) => match entries.get("sync") {
            Some(serde_json::Value::Bool(enabled)) => Ok(*enabled),
            Some(_) => anyhow::bail!("{}.sync must be a boolean", path.display()),
            None => Ok(false),
        },
        serde_json::Value::Array(entries) => {
            let mut enabled = false;
            for entry in entries {
                let serde_json::Value::String(plugin_id) = entry else {
                    anyhow::bail!("{} must contain only plugin IDs", path.display());
                };
                enabled |= plugin_id == "sync";
            }
            Ok(enabled)
        }
        _ => anyhow::bail!(
            "{} must be an object or an array of plugin IDs",
            path.display()
        ),
    }
}

/// Aggregated result of a vault conflict-file scan.
#[derive(Debug)]
pub struct SyncConflictReport {
    /// Paths of conflict-marker files found in the vault.
    pub conflicts: Vec<PathBuf>,
    /// Number of file-system entries examined (files + dirs).
    pub scanned: usize,
}

impl SyncConflictReport {
    /// Human-readable operator warning, or `None` when the vault is clean.
    ///
    /// Intended for `tracing::warn!` at the sync entry point.
    pub fn describe(&self) -> Option<String> {
        if self.conflicts.is_empty() {
            return None;
        }
        let paths = self
            .conflicts
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!(
            "{} sync-conflict file(s) detected in the vault — resolve them before \
             NEOTH writes, or its writes may collide: {}",
            self.conflicts.len(),
            paths,
        ))
    }
}

/// Returns `true` when `name` matches a well-known cloud-sync conflict pattern.
///
/// Patterns covered:
/// - Syncthing:  `*.sync-conflict-*`                (e.g. `note.sync-conflict-20240101-ABC.md`)
/// - Dropbox / iCloud: `* (conflicted copy *)*`     (e.g. `note (conflicted copy 2024-01-01).md`)
///   Also matches variants without parentheses: `*conflicted copy*`
/// - Generic:    `*.conflict.*`                      (e.g. `note.conflict.1.md`)
fn is_conflict_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains(".sync-conflict-") || lower.contains("conflicted copy") || {
        // `*.conflict.*` — must have a dot before AND after "conflict"
        // to avoid matching file names that merely contain the word.
        let mut it = lower.splitn(3, ".conflict.");
        it.next().is_some() && it.next().map(|s| !s.is_empty()).unwrap_or(false)
    }
}

/// Walk `vault_dir` and collect every file whose name matches a cloud-sync
/// conflict pattern (Syncthing, Dropbox, iCloud, …).
///
/// Hidden directories (names starting with `.`) are skipped — `.obsidian/`
/// and `.git/` store metadata that the sync clients may legitimately name with
/// unusual characters and that the operator should not need to touch.
///
/// # Robustness
/// - Any unreadable directory/entry or unsupported symlink/special file returns
///   an error. The sync caller treats an incomplete scan as a write blocker.
/// - If `vault_dir` does not exist, returns an empty report.
/// - No allocation beyond the result `Vec`; the walk is done with a plain
///   stack (`Vec<PathBuf>`) to avoid a `walkdir` dependency.
pub fn detect_sync_conflicts(vault_dir: &Path) -> Result<SyncConflictReport> {
    let mut conflicts = Vec::new();
    let mut scanned = 0usize;

    let root_metadata = match std::fs::symlink_metadata(vault_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SyncConflictReport { conflicts, scanned });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Obsidian vault root {}", vault_dir.display()));
        }
    };
    if !root_metadata.file_type().is_dir() {
        anyhow::bail!(
            "Obsidian vault root is not a traversable directory: {}",
            vault_dir.display()
        );
    }

    // Iterative DFS to avoid stack overflow on deep vaults.
    let mut stack = vec![vault_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let rd = std::fs::read_dir(&dir)
            .with_context(|| format!("scan Obsidian vault directory {}", dir.display()))?;

        for entry in rd {
            let entry = entry.with_context(|| {
                format!("read entry under Obsidian vault dir {}", dir.display())
            })?;
            scanned += 1;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let file_type = entry
                .file_type()
                .with_context(|| format!("inspect Obsidian vault entry {}", path.display()))?;

            // Skip hidden directories (`.obsidian`, `.git`, etc.), but still
            // inspect hidden files whose names carry a conflict marker.
            if file_type.is_dir() && name_str.starts_with('.') {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if is_conflict_name(&name_str) {
                    conflicts.push(path);
                }
            } else {
                anyhow::bail!(
                    "unsupported symlink or special file in Obsidian vault scan: {}",
                    path.display()
                );
            }
        }
    }

    Ok(SyncConflictReport { conflicts, scanned })
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
        assert!(
            cache.is_changed(&p),
            "missing dir must be treated as changed"
        );
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

    // ── IGNIS-04 detect_sync_conflicts ──────────────────────────────────────

    #[test]
    fn core_sync_guard_accepts_object_and_array_shapes() {
        let dir = tempdir().unwrap();
        let obsidian = dir.path().join(".obsidian");
        std::fs::create_dir_all(&obsidian).unwrap();
        let config = obsidian.join("core-plugins.json");

        std::fs::write(&config, br#"{"sync":true,"file-explorer":true}"#).unwrap();
        assert!(obsidian_core_sync_enabled(dir.path()).unwrap());

        std::fs::write(&config, br#"["file-explorer","sync"]"#).unwrap();
        assert!(obsidian_core_sync_enabled(dir.path()).unwrap());

        std::fs::write(&config, br#"{"sync":false}"#).unwrap();
        assert!(!obsidian_core_sync_enabled(dir.path()).unwrap());
    }

    #[test]
    fn core_sync_guard_missing_is_disabled_and_malformed_fails_closed() {
        let dir = tempdir().unwrap();
        assert!(!obsidian_core_sync_enabled(dir.path()).unwrap());

        let obsidian = dir.path().join(".obsidian");
        std::fs::create_dir_all(&obsidian).unwrap();
        let config = obsidian.join("core-plugins.json");
        std::fs::write(&config, b"not-json").unwrap();
        assert!(obsidian_core_sync_enabled(dir.path()).is_err());

        std::fs::write(&config, br#"{"sync":"yes"}"#).unwrap();
        assert!(obsidian_core_sync_enabled(dir.path()).is_err());
    }

    #[test]
    fn conflict_detector_finds_syncthing_and_dropbox_patterns() {
        let dir = tempdir().unwrap();

        // Syncthing conflict file.
        std::fs::write(
            dir.path().join("note.sync-conflict-20240101-ABCDEF.md"),
            b"syncthing conflict",
        )
        .unwrap();

        // Dropbox / iCloud "conflicted copy" variant.
        std::fs::write(
            dir.path().join("report (conflicted copy 2024-01-01).md"),
            b"dropbox conflict",
        )
        .unwrap();

        let report = detect_sync_conflicts(dir.path()).unwrap();
        assert_eq!(
            report.conflicts.len(),
            2,
            "both conflict files must be detected; got {:?}",
            report.conflicts
        );
        assert!(report.scanned >= 2);
        assert!(report.describe().is_some());
        assert!(report.describe().unwrap().contains("2 sync-conflict"));
    }

    #[test]
    fn conflict_detector_clean_vault_returns_empty() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("daily-note.md"), b"# 2024-01-01").unwrap();
        std::fs::write(dir.path().join("todo.md"), b"- [ ] thing").unwrap();

        let report = detect_sync_conflicts(dir.path()).unwrap();
        assert!(
            report.conflicts.is_empty(),
            "clean vault must produce no conflicts"
        );
        assert!(report.describe().is_none());
    }

    #[test]
    fn conflict_detector_skips_hidden_obsidian_dir() {
        let dir = tempdir().unwrap();

        // Conflict file hidden inside .obsidian — must be skipped.
        let obsidian = dir.path().join(".obsidian");
        std::fs::create_dir_all(&obsidian).unwrap();
        std::fs::write(
            obsidian.join("core-plugins.sync-conflict-20240101-XYZ.json"),
            b"{}",
        )
        .unwrap();

        // Clean note at the vault root — should not appear in conflicts.
        std::fs::write(dir.path().join("note.md"), b"# note").unwrap();

        let report = detect_sync_conflicts(dir.path()).unwrap();
        assert!(
            report.conflicts.is_empty(),
            "conflict file inside .obsidian must be skipped; got {:?}",
            report.conflicts
        );
    }

    #[test]
    fn conflict_detector_absent_vault_returns_empty() {
        let report = detect_sync_conflicts(std::path::Path::new(
            "/nonexistent/vault/that/does/not/exist",
        ))
        .unwrap();
        assert!(report.conflicts.is_empty());
        assert_eq!(report.scanned, 0);
        assert!(report.describe().is_none());
    }

    #[test]
    fn conflict_detector_generic_dot_conflict_dot_pattern() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("note.conflict.1.md"), b"generic conflict").unwrap();
        // Plain name with "conflict" as a whole word but no surrounding dots — not a match.
        std::fs::write(dir.path().join("conflict-log.md"), b"not a conflict file").unwrap();

        let report = detect_sync_conflicts(dir.path()).unwrap();
        assert_eq!(
            report.conflicts.len(),
            1,
            "only the *.conflict.* pattern should match; got {:?}",
            report.conflicts
        );
    }

    #[test]
    fn conflict_detector_fails_closed_when_root_cannot_be_traversed() {
        let dir = tempdir().unwrap();
        let not_a_directory = dir.path().join("vault-file");
        std::fs::write(&not_a_directory, b"not a directory").unwrap();

        let error = detect_sync_conflicts(&not_a_directory).unwrap_err();
        assert!(
            error.to_string().contains("not a traversable directory"),
            "traversal failure must be surfaced, not interpreted as a clean vault: {error:#}"
        );
    }
}
