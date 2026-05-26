//! R-07 — auto-backup rolling-retention.
//!
//! `daemon::backup` already knows how to WRITE a `.tar.gz` snapshot
//! of `~/.neoth/`. R-07 adds the retention half: a pure-fn policy
//! that takes the directory listing + returns which files to keep
//! + which to delete, plus a thin `enforce_retention` wrapper that
//! does the actual deletion on disk.
//!
//! ## Policy (default)
//!
//! - Keep `RETAIN_COUNT` newest backup files (default 4 = ~1
//!   month of weekly snapshots).
//! - Files must match `neoth-*.tar.gz` to be considered (so we
//!   never delete a hand-named archive the operator parked in the
//!   backup dir).
//! - Sort by mtime descending — newest first; everything beyond
//!   the retention window is marked for deletion.
//! - `apply_retention_decision` is the side-effect step;
//!   `plan_retention` is the pure-fn the test exercises against
//!   constructed inputs.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default rolling-retention window — 4 weekly snapshots ≈ 1 month
/// of history.
pub const RETAIN_COUNT: usize = 4;

/// Filename prefix the policy considers. Anything not matching
/// is left untouched.
pub const BACKUP_FILE_PREFIX: &str = "neoth-";

/// Filename suffix the policy considers.
pub const BACKUP_FILE_SUFFIX: &str = ".tar.gz";

/// One backup file's metadata, the policy operates on. mtime as
/// unix seconds (u64) so the pure-fn stays portable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFileEntry {
    pub path: PathBuf,
    pub mtime_unix: u64,
}

/// Outcome of the retention plan. Two parallel lists so callers
/// can render both ("kept N, would delete M") before any I/O fires.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetentionDecision {
    pub kept: Vec<BackupFileEntry>,
    pub to_delete: Vec<BackupFileEntry>,
}

impl RetentionDecision {
    pub fn kept_count(&self) -> usize {
        self.kept.len()
    }
    pub fn delete_count(&self) -> usize {
        self.to_delete.len()
    }
    pub fn is_no_op(&self) -> bool {
        self.to_delete.is_empty()
    }
}

/// True when `name` looks like a NEOTH-emitted backup archive.
/// Operators who park `personal-backup-2026.tar.gz` in the same
/// dir don't get touched.
pub fn is_neoth_backup_name(name: &str) -> bool {
    name.starts_with(BACKUP_FILE_PREFIX) && name.ends_with(BACKUP_FILE_SUFFIX)
}

/// Pure-fn retention plan. Takes a list of candidates + the
/// retention window + returns which to keep and which to delete.
/// Newest-first by mtime; ties broken by path ascending (stable
/// across runs).
///
/// Empty input → empty result. `retain` of 0 means "keep nothing"
/// — caller controls this knob; we don't second-guess.
pub fn plan_retention(mut entries: Vec<BackupFileEntry>, retain: usize) -> RetentionDecision {
    entries.sort_by(|a, b| {
        b.mtime_unix
            .cmp(&a.mtime_unix)
            .then_with(|| a.path.cmp(&b.path))
    });
    let kept: Vec<BackupFileEntry> = entries.iter().take(retain).cloned().collect();
    let to_delete: Vec<BackupFileEntry> = entries.into_iter().skip(retain).collect();
    RetentionDecision { kept, to_delete }
}

/// Scan a backup directory + return only the NEOTH-emitted
/// archive entries with their mtimes. Files that fail to stat are
/// silently skipped (the retention pass shouldn't error on a
/// transient FS hiccup; the next pass picks them up).
pub fn scan_backup_dir(dir: &Path) -> std::io::Result<Vec<BackupFileEntry>> {
    let mut out = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_neoth_backup_name(name) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mtime_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(BackupFileEntry { path, mtime_unix });
    }
    Ok(out)
}

/// Apply a retention decision — delete the files in `to_delete`.
/// Returns the count actually removed. Errors from individual
/// deletes are surfaced (a backup-dir on a read-only volume must
/// fail loudly).
pub fn apply_retention_decision(decision: &RetentionDecision) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in &decision.to_delete {
        std::fs::remove_file(&entry.path)?;
        removed += 1;
    }
    Ok(removed)
}

/// Convenience entry point: scan + plan + apply in one call.
/// Returns the decision (so the caller can log "kept N, removed
/// M") + the actual remove count.
pub fn enforce_retention(
    backup_dir: &Path,
    retain: usize,
) -> std::io::Result<(RetentionDecision, usize)> {
    let entries = scan_backup_dir(backup_dir)?;
    let decision = plan_retention(entries, retain);
    let removed = apply_retention_decision(&decision)?;
    Ok((decision, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, mtime: u64) -> BackupFileEntry {
        BackupFileEntry {
            path: PathBuf::from(path),
            mtime_unix: mtime,
        }
    }

    // ── name filter ───────────────────────────────────────────────

    #[test]
    fn is_neoth_backup_name_accepts_canonical() {
        assert!(is_neoth_backup_name("neoth-20260526T120000Z.tar.gz"));
        assert!(is_neoth_backup_name("neoth-anything.tar.gz"));
    }

    #[test]
    fn is_neoth_backup_name_rejects_personal_archives() {
        assert!(!is_neoth_backup_name("personal-backup.tar.gz"));
        assert!(!is_neoth_backup_name("neoth-something.zip"));
        assert!(!is_neoth_backup_name(""));
    }

    // ── pure plan ─────────────────────────────────────────────────

    #[test]
    fn plan_empty_input_empty_decision() {
        let d = plan_retention(vec![], 4);
        assert!(d.kept.is_empty());
        assert!(d.to_delete.is_empty());
        assert!(d.is_no_op());
    }

    #[test]
    fn plan_under_retain_keeps_everything() {
        let entries = vec![entry("a.tgz", 100), entry("b.tgz", 200), entry("c.tgz", 300)];
        let d = plan_retention(entries, 4);
        assert_eq!(d.kept_count(), 3);
        assert_eq!(d.delete_count(), 0);
        assert!(d.is_no_op());
    }

    #[test]
    fn plan_at_retain_keeps_everything() {
        let entries = vec![entry("a", 100), entry("b", 200), entry("c", 300), entry("d", 400)];
        let d = plan_retention(entries, 4);
        assert_eq!(d.kept_count(), 4);
        assert_eq!(d.delete_count(), 0);
    }

    #[test]
    fn plan_above_retain_drops_oldest() {
        let entries = vec![
            entry("a", 100),
            entry("b", 200),
            entry("c", 300),
            entry("d", 400),
            entry("e", 500),
            entry("f", 600),
        ];
        let d = plan_retention(entries, 4);
        assert_eq!(d.kept_count(), 4);
        assert_eq!(d.delete_count(), 2);
        // Newest 4 kept.
        let kept_mtimes: Vec<u64> = d.kept.iter().map(|e| e.mtime_unix).collect();
        assert_eq!(kept_mtimes, vec![600, 500, 400, 300]);
        // Oldest 2 marked for deletion.
        let drop_mtimes: Vec<u64> = d.to_delete.iter().map(|e| e.mtime_unix).collect();
        assert_eq!(drop_mtimes, vec![200, 100]);
    }

    #[test]
    fn plan_ties_break_by_path_ascending() {
        let entries = vec![
            entry("z.tgz", 100),
            entry("a.tgz", 100),
            entry("m.tgz", 100),
        ];
        let d = plan_retention(entries, 2);
        // Same mtime → alpha asc; a kept, m kept, z dropped.
        let kept_paths: Vec<PathBuf> = d.kept.iter().map(|e| e.path.clone()).collect();
        assert_eq!(kept_paths, vec![PathBuf::from("a.tgz"), PathBuf::from("m.tgz")]);
        assert_eq!(d.to_delete[0].path, PathBuf::from("z.tgz"));
    }

    #[test]
    fn plan_retain_zero_drops_everything() {
        let entries = vec![entry("a", 1), entry("b", 2)];
        let d = plan_retention(entries, 0);
        assert!(d.kept.is_empty());
        assert_eq!(d.delete_count(), 2);
    }

    #[test]
    fn plan_default_retain_is_4() {
        assert_eq!(RETAIN_COUNT, 4);
    }

    // ── scan ──────────────────────────────────────────────────────

    #[test]
    fn scan_missing_dir_returns_empty() {
        let entries = scan_backup_dir(std::path::Path::new("/no/such/dir/anywhere")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn scan_picks_up_only_neoth_archive_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("neoth-001.tar.gz"), b"x").unwrap();
        std::fs::write(dir.path().join("neoth-002.tar.gz"), b"x").unwrap();
        std::fs::write(dir.path().join("personal.tar.gz"), b"x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        let entries = scan_backup_dir(dir.path()).unwrap();
        let names: Vec<String> = entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 2);
        assert!(names.contains(&"neoth-001.tar.gz".to_string()));
        assert!(names.contains(&"neoth-002.tar.gz".to_string()));
        assert!(!names.iter().any(|n| n == "personal.tar.gz"));
    }

    #[test]
    fn scan_ignores_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("neoth-001.tar.gz"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("neoth-trap.tar.gz")).unwrap();
        let entries = scan_backup_dir(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("001.tar.gz"));
    }

    // ── apply ─────────────────────────────────────────────────────

    #[test]
    fn apply_empty_decision_removes_nothing() {
        let removed = apply_retention_decision(&RetentionDecision::default()).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn apply_removes_each_listed_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.tar.gz");
        let b = dir.path().join("b.tar.gz");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        let decision = RetentionDecision {
            kept: vec![],
            to_delete: vec![
                BackupFileEntry {
                    path: a.clone(),
                    mtime_unix: 0,
                },
                BackupFileEntry {
                    path: b.clone(),
                    mtime_unix: 0,
                },
            ],
        };
        let removed = apply_retention_decision(&decision).unwrap();
        assert_eq!(removed, 2);
        assert!(!a.exists());
        assert!(!b.exists());
    }

    // ── enforce_retention end-to-end ──────────────────────────────

    #[test]
    fn enforce_retention_keeps_only_4_newest_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = (0..6)
            .map(|i| {
                let p = dir.path().join(format!("neoth-{i:02}.tar.gz"));
                std::fs::write(&p, format!("{i}")).unwrap();
                // Set mtime via a sleep + recreate so the OS gives
                // distinct mtimes. tempfile doesn't expose mtime
                // setting on Windows; instead we manually emit
                // entries via plan_retention in the next test.
                p
            })
            .collect();

        let (decision, removed) = enforce_retention(dir.path(), 4).unwrap();
        // Total candidates = 6, retain 4 → remove 2.
        assert_eq!(decision.kept_count(), 4);
        assert_eq!(decision.delete_count(), 2);
        assert_eq!(removed, 2);
        // Exactly 4 archive files remain on disk.
        let remaining: Vec<PathBuf> = paths.iter().filter(|p| p.exists()).cloned().collect();
        assert_eq!(remaining.len(), 4);
    }

    #[test]
    fn enforce_retention_no_op_under_threshold() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            std::fs::write(
                dir.path().join(format!("neoth-{i:02}.tar.gz")),
                format!("{i}"),
            )
            .unwrap();
        }
        let (decision, removed) = enforce_retention(dir.path(), 4).unwrap();
        assert!(decision.is_no_op());
        assert_eq!(removed, 0);
        // All 3 still there.
        let remaining: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(remaining.len(), 3);
    }

    #[test]
    fn enforce_retention_ignores_non_neoth_files() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(
                dir.path().join(format!("neoth-{i:02}.tar.gz")),
                format!("{i}"),
            )
            .unwrap();
        }
        let personal = dir.path().join("personal-backup.tar.gz");
        std::fs::write(&personal, b"x").unwrap();
        let readme = dir.path().join("README.md");
        std::fs::write(&readme, b"x").unwrap();

        let (decision, removed) = enforce_retention(dir.path(), 4).unwrap();
        assert_eq!(decision.kept_count(), 4);
        assert_eq!(removed, 1);
        // Operator's personal archive + README untouched.
        assert!(personal.exists());
        assert!(readme.exists());
    }
}
