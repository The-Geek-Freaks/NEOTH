//! GOLD-ADAPT-MEM-05 — Pre-compaction backup + persisted counter.
//!
//! Inspired by Jarvis `hooks/pre-compact-backup.sh`.
//!
//! ## What this does
//!
//! Before any memory compaction event fires, the guard:
//! 1. **Snapshots the current session state** as a JSON backup under
//!    `~/.neoth/compaction_backups/<counter>-<timestamp>.json`.
//! 2. **Bumps a persisted compaction counter** in
//!    `~/.neoth/compaction_count.json` so every backup carries a
//!    monotonically-increasing index (survives daemon restarts).
//!
//! A bad compaction is therefore recoverable: restore the latest
//! backup, decrement the counter, and replay from there.
//!
//! ## Recovery path
//!
//! [`latest_backup`] returns the path of the most recent backup
//! (highest counter). Callers can read it, inspect it, and re-hydrate
//! session state. [`restore_latest`] reads the JSON back into a
//! [`CompactionBackup`].
//!
//! ## Wire integration
//!
//! The `cli/chat.rs` compaction wire is DEFERRED (the compaction
//! event only fires from the context/dispatch loop which is a
//! parallel-hot caller). This module is standalone and headless-tested
//! (no async, no DB, no provider). Wire as a follow-up once the
//! dispatch loop exposes a pre-compact hook.
//!
//! ## Safety
//!
//! - All I/O is best-effort: a failing backup write is logged but
//!   NEVER blocks or returns an error to the caller (a bad disk must
//!   not prevent compaction from proceeding).
//! - Counter persistence uses atomic rename (`.tmp` → final) so a
//!   crash between the write and the rename leaves the previous count
//!   intact.
//! - The backup directory is created lazily on first use.
//! - No operator-controlled path components in backup filenames
//!   (counter + unix-seconds only) → no path-traversal surface.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── Persistent counter ────────────────────────────────────────────────────────

/// File that stores the ever-increasing compaction count.
/// `~/.neoth/compaction_count.json`
pub fn counter_path(neoth_home: &Path) -> PathBuf {
    neoth_home.join("compaction_count.json")
}

/// Read the current counter. Returns 0 on a missing or corrupt file
/// (cold start; counter will start from 1 on the first bump).
pub fn read_counter(neoth_home: &Path) -> u64 {
    let path = counter_path(neoth_home);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str::<CounterFile>(&s)
            .map(|c| c.count)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Bump the counter atomically (write to `.tmp`, rename). Returns the
/// NEW value. On any I/O error the in-memory increment is returned but
/// the disk state is left unchanged — the daemon can keep running
/// without durable persistence.
pub fn bump_counter(neoth_home: &Path) -> u64 {
    let next = read_counter(neoth_home).saturating_add(1);
    let path = counter_path(neoth_home);
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_string(&CounterFile { count: next })
        .unwrap_or_else(|_| "{\"count\":1}".into());
    match fs::write(&tmp, body.as_bytes()) {
        Ok(()) => {
            if let Err(e) = fs::rename(&tmp, &path) {
                tracing::warn!(error = %e, "compaction_guard: counter rename failed");
                let _ = fs::remove_file(&tmp);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "compaction_guard: counter write failed");
        }
    }
    next
}

// ── Backup ────────────────────────────────────────────────────────────────────

/// The session state snapshot written before each compaction.
///
/// Fields are intentionally open (a `HashMap` catch-all) so callers
/// can attach arbitrary key/value context without changing the schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionBackup {
    /// Monotonically-increasing compaction index (from the counter).
    pub compaction_index: u64,
    /// Unix seconds at snapshot time.
    pub snapshot_ts: i64,
    /// Free-form session context supplied by the caller. Any
    /// serialisable key/value pairs — prompt length, session id, etc.
    pub context: std::collections::BTreeMap<String, serde_json::Value>,
    /// Optional verbatim session state (e.g. a prompt excerpt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
}

impl CompactionBackup {
    /// Build a new backup. `now_unix` is wall-clock unix seconds (passed
    /// in so tests can control the clock without system calls).
    pub fn new(
        compaction_index: u64,
        now_unix: i64,
        context: std::collections::BTreeMap<String, serde_json::Value>,
        session_state: Option<String>,
    ) -> Self {
        Self {
            compaction_index,
            snapshot_ts: now_unix,
            context,
            session_state,
        }
    }
}

/// Directory under `neoth_home` where backups are stored.
pub fn backup_dir(neoth_home: &Path) -> PathBuf {
    neoth_home.join("compaction_backups")
}

/// Canonical filename for a backup: `<index>-<ts_unix>.json`.
/// No operator-controlled components — safe from path traversal.
fn backup_filename(index: u64, ts_unix: i64) -> String {
    format!("{index:08}-{ts_unix}.json")
}

/// Persist a [`CompactionBackup`] to disk. Returns the path of the
/// written file on success. Best-effort: returns `None` on I/O error
/// (the caller must not block on backup success).
pub fn write_backup(neoth_home: &Path, backup: &CompactionBackup) -> Option<PathBuf> {
    let dir = backup_dir(neoth_home);
    if let Err(e) = fs::create_dir_all(&dir) {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "compaction_guard: could not create backup dir"
        );
        return None;
    }
    let name = backup_filename(backup.compaction_index, backup.snapshot_ts);
    let final_path = dir.join(&name);
    let tmp_path = dir.join(format!("{name}.tmp"));
    let body = match serde_json::to_string_pretty(backup) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "compaction_guard: backup serialize failed");
            return None;
        }
    };
    match fs::write(&tmp_path, body.as_bytes()) {
        Ok(()) => match fs::rename(&tmp_path, &final_path) {
            Ok(()) => Some(final_path),
            Err(e) => {
                tracing::warn!(
                    path = %final_path.display(),
                    error = %e,
                    "compaction_guard: backup rename failed"
                );
                let _ = fs::remove_file(&tmp_path);
                None
            }
        },
        Err(e) => {
            tracing::warn!(
                path = %tmp_path.display(),
                error = %e,
                "compaction_guard: backup write failed"
            );
            None
        }
    }
}

// ── High-level API ────────────────────────────────────────────────────────────

/// **Primary entry point.** Call this BEFORE triggering any compaction.
///
/// 1. Bumps the persisted counter.
/// 2. Writes a backup snapshot to `~/.neoth/compaction_backups/`.
///
/// Returns `(new_index, backup_path_opt)`. `backup_path_opt` is `None`
/// when the write failed — callers may log but must not abort the
/// compaction because of it.
pub fn pre_compact(
    neoth_home: &Path,
    now_unix: i64,
    context: std::collections::BTreeMap<String, serde_json::Value>,
    session_state: Option<String>,
) -> (u64, Option<PathBuf>) {
    let index = bump_counter(neoth_home);
    let backup = CompactionBackup::new(index, now_unix, context, session_state);
    let path = write_backup(neoth_home, &backup);
    (index, path)
}

// ── Recovery ──────────────────────────────────────────────────────────────────

/// Find the most recent backup file (highest counter prefix).
/// Returns `None` when the backup directory is empty or absent.
pub fn latest_backup(neoth_home: &Path) -> Option<PathBuf> {
    let dir = backup_dir(neoth_home);
    let entries = fs::read_dir(&dir).ok()?;
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "json").unwrap_or(false)
                && !p
                    .file_name()
                    .map(|n| n.to_string_lossy().ends_with(".tmp"))
                    .unwrap_or(false)
        })
        .collect();
    // Sort lexicographically — `<08-digit index>-<ts>` sorts correctly.
    candidates.sort();
    candidates.into_iter().next_back()
}

/// Read and deserialize the latest backup. Returns `None` when no
/// backup exists or the file is unreadable / corrupt.
pub fn restore_latest(neoth_home: &Path) -> Option<CompactionBackup> {
    let path = latest_backup(neoth_home)?;
    let s = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&s).ok()
}

// ── Internal types ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct CounterFile {
    count: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn home() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn ctx(k: &str, v: &str) -> BTreeMap<String, serde_json::Value> {
        let mut m = BTreeMap::new();
        m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        m
    }

    // ── counter ──────────────────────────────────────────────────────────────

    #[test]
    fn counter_starts_at_zero_on_missing_file() {
        let h = home();
        assert_eq!(read_counter(h.path()), 0);
    }

    #[test]
    fn bump_counter_increments_and_persists() {
        let h = home();
        let n1 = bump_counter(h.path());
        assert_eq!(n1, 1);
        let n2 = bump_counter(h.path());
        assert_eq!(n2, 2);
        // Reading directly from disk should match the last bump.
        assert_eq!(read_counter(h.path()), 2);
    }

    #[test]
    fn counter_survives_multiple_bumps() {
        let h = home();
        for expected in 1..=5u64 {
            assert_eq!(bump_counter(h.path()), expected);
        }
        assert_eq!(read_counter(h.path()), 5);
    }

    // ── backup ───────────────────────────────────────────────────────────────

    #[test]
    fn write_backup_creates_file_and_returns_path() {
        let h = home();
        let backup = CompactionBackup::new(1, 1_700_000_000, ctx("session", "s1"), None);
        let path = write_backup(h.path(), &backup).expect("write_backup must succeed");
        assert!(path.exists(), "backup file must exist on disk");
        assert!(path.extension().map(|e| e == "json").unwrap_or(false));
    }

    #[test]
    fn write_backup_no_tmp_files_left_behind() {
        let h = home();
        let backup = CompactionBackup::new(2, 1_700_000_001, ctx("k", "v"), Some("state".into()));
        write_backup(h.path(), &backup).unwrap();
        let dir = backup_dir(h.path());
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            assert!(
                !p.to_string_lossy().ends_with(".tmp"),
                "no .tmp files: {p:?}"
            );
        }
    }

    #[test]
    fn backup_roundtrip_preserves_all_fields() {
        let h = home();
        let mut c = BTreeMap::new();
        c.insert("prompt_len".to_string(), serde_json::json!(1234));
        let original = CompactionBackup::new(3, 1_700_000_002, c, Some("session xyz".into()));
        let path = write_backup(h.path(), &original).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let decoded: CompactionBackup = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded.compaction_index, 3);
        assert_eq!(decoded.snapshot_ts, 1_700_000_002);
        assert_eq!(decoded.session_state.as_deref(), Some("session xyz"));
        assert_eq!(decoded.context["prompt_len"], serde_json::json!(1234));
    }

    // ── latest_backup / restore ───────────────────────────────────────────────

    #[test]
    fn latest_backup_none_when_dir_absent() {
        let h = home();
        assert!(latest_backup(h.path()).is_none());
    }

    #[test]
    fn latest_backup_returns_highest_index() {
        let h = home();
        // Write backups in non-sequential order to confirm sorting is by name.
        write_backup(h.path(), &CompactionBackup::new(1, 1_000, ctx("x", "a"), None)).unwrap();
        write_backup(h.path(), &CompactionBackup::new(3, 3_000, ctx("x", "c"), None)).unwrap();
        write_backup(h.path(), &CompactionBackup::new(2, 2_000, ctx("x", "b"), None)).unwrap();
        let latest = latest_backup(h.path()).unwrap();
        let name = latest.file_name().unwrap().to_string_lossy();
        assert!(
            name.starts_with("00000003-"),
            "expected index 3, got {name}"
        );
    }

    #[test]
    fn restore_latest_round_trips_last_written() {
        let h = home();
        write_backup(h.path(), &CompactionBackup::new(1, 1_000, ctx("a", "1"), None)).unwrap();
        write_backup(h.path(), &CompactionBackup::new(2, 2_000, ctx("b", "2"), None)).unwrap();
        let restored = restore_latest(h.path()).expect("restore_latest must succeed");
        assert_eq!(restored.compaction_index, 2, "latest index must be 2");
        assert_eq!(restored.context["b"], serde_json::json!("2"));
    }

    // ── pre_compact high-level ────────────────────────────────────────────────

    #[test]
    fn pre_compact_bumps_counter_and_writes_backup() {
        let h = home();
        let (index, path) = pre_compact(h.path(), 9_999, ctx("tok", "512"), None);
        assert_eq!(index, 1, "first call → index 1");
        assert!(path.is_some(), "backup file must be written");
        assert!(path.unwrap().exists());
        assert_eq!(read_counter(h.path()), 1);
    }

    #[test]
    fn pre_compact_second_call_increments_index() {
        let h = home();
        let (i1, _) = pre_compact(h.path(), 1_000, ctx("a", "1"), None);
        let (i2, _) = pre_compact(h.path(), 2_000, ctx("b", "2"), None);
        assert_eq!(i1, 1);
        assert_eq!(i2, 2);
        // The latest backup on disk is the one from the second call.
        let restored = restore_latest(h.path()).unwrap();
        assert_eq!(restored.compaction_index, 2);
    }

    #[test]
    fn restore_latest_none_on_empty_backup_dir() {
        let h = home();
        assert!(restore_latest(h.path()).is_none());
    }
}
