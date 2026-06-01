//! R-02 (Session 24) — `.bak` snapshot-on-shrink + startup compare-and-restore.
//!
//! Tracked files (`views.db`, `freedom.yaml`, `wizard_checkpoint.json`,
//! …) get a `.bak` companion written ONLY when a new payload would
//! shrink them. A truncate-then-write that silently dropped half the
//! operator's profile rows would otherwise leave no trace; the .bak
//! lets the recovery flow (R-06 `neoth recover`) offer the operator a
//! roll-back.
//!
//! ## What this module is + isn't
//!
//! - **Is**: a pure helper crate plus a startup scanner. No daemon
//!   wiring lives here — callers opt in by routing their atomic-write
//!   path through [`shrink_safe_write`] instead of `std::fs::write` /
//!   `tempfile + rename`.
//! - **Isn't**: a generic backup system. Files OUTSIDE the tracked
//!   set are ignored. Auto-scheduled rotating backups are a separate
//!   item (R-07) shipping later.
//!
//! ## On-disk shape
//!
//! For a file at `~/.neoth/freedom.yaml` the bak lives at
//! `~/.neoth/freedom.yaml.bak`. One bak per tracked file — repeated
//! shrinks overwrite the bak so the operator always has the **most
//! recent pre-shrink state**, not an unbounded archive. R-07 owns
//! the rolling-archive variant.
//!
//! ## Why "shrink-only", not "every write"
//!
//! Routine atomic-rename writes that produce identical-size content
//! (e.g. profile preset switch) DO NOT trigger a bak — the file is
//! semantically the same shape and the .bak would just churn the
//! disk. Shrink is the canonical "operator might have lost data"
//! signal: the new file has fewer rows / smaller config / less
//! state than the old one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub mod turn_journal;
pub use turn_journal::{JournalReport, TurnEvent, TurnJournal, scan_for_journals};

/// Atomically write `new_content` to `path`. When the new content is
/// strictly shorter than the existing file, first copy the existing
/// file to `<path>.bak` so the pre-shrink state survives.
///
/// Same-size or larger writes skip the bak step entirely. Use this
/// in place of `std::fs::write` for any config / state file an
/// operator would care about restoring.
///
/// Returns `true` when a bak was actually written, `false` otherwise
/// — useful for the audit trail.
pub fn shrink_safe_write(path: &Path, new_content: &[u8]) -> Result<bool> {
    let bak_written = match std::fs::metadata(path) {
        Ok(meta) if meta.len() as usize > new_content.len() => {
            // New content shrinks the file → snapshot first.
            let bak = bak_path(path);
            std::fs::copy(path, &bak)
                .with_context(|| format!("snapshot {} -> {}", path.display(), bak.display()))?;
            true
        }
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Fresh write — no pre-shrink state to preserve.
            false
        }
        Err(e) => return Err(e).context(format!("stat {}", path.display())),
    };

    // Atomic rename via .tmp companion (matches the rest of the
    // credentials-write surface so partial writes are never observable
    // by a concurrent reader).
    let tmp = path.with_extension(extension_with_tmp(path));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    std::fs::write(&tmp, new_content).with_context(|| format!("write tmp {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(bak_written)
}

/// Canonical `.bak` companion path for `target`. Public so the
/// `neoth recover` CLI (R-06) can derive the bak filename without
/// re-implementing the rule.
pub fn bak_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".bak");
    PathBuf::from(s)
}

fn extension_with_tmp(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.tmp"),
        None => "tmp".to_string(),
    }
}

/// One row in [`scan_for_baks`] — pairs a `.bak` file with metadata
/// about the live file (or its absence) so the operator can decide
/// whether to restore.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BakReport {
    /// Absolute path to the `.bak` file.
    pub bak_path: PathBuf,
    /// Size of the `.bak` in bytes.
    pub bak_size: u64,
    /// Absolute path to the live file the bak shadowed.
    pub live_path: PathBuf,
    /// Size of the live file in bytes, `None` when it's missing.
    pub live_size: Option<u64>,
    /// Operator-visible verdict — used by the R-06 UI layer.
    pub verdict: BakVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BakVerdict {
    /// `.bak` file is older + smaller-or-equal than the live file —
    /// safe to discard. (R-06 will offer `--clean` for this case.)
    Stale,
    /// Live file is missing entirely. Operator likely wants to restore.
    LiveMissing,
    /// Live file exists but is strictly smaller than the bak —
    /// the shrink that caused this bak was NOT compensated by a
    /// later growth, so the operator probably lost data.
    LiveShrunk,
    /// Live file is the same size as or larger than the bak.
    /// Default-safe state.
    LiveOk,
}

/// Walk `home` for `*.bak` files and pair each with its live
/// counterpart. Recursive into one level of subdirectories
/// (`~/.neoth/wal/000001.wal.bak` is reachable). Returns reports
/// sorted by `live_path` for deterministic operator output.
///
/// Tolerates a missing `home` (returns empty vec) so the R-06 CLI
/// can run against a fresh install without erroring.
pub fn scan_for_baks(home: &Path) -> Result<Vec<BakReport>> {
    let mut reports = Vec::new();
    walk_for_baks(home, 0, 2, &mut reports)?;
    reports.sort_by(|a, b| a.live_path.cmp(&b.live_path));
    Ok(reports)
}

fn walk_for_baks(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<BakReport>,
) -> Result<()> {
    if depth > max_depth {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("read_dir {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_for_baks(&path, depth + 1, max_depth, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if !name.ends_with(".bak") {
            continue;
        }
        // .tmp.bak / .bak.tmp from a torn write — skip.
        if name.contains(".tmp") {
            continue;
        }
        let bak_size = entry.metadata()?.len();
        let live_path = strip_bak_suffix(&path);
        let live_size = match std::fs::metadata(&live_path) {
            Ok(m) => Some(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(e).context(format!("stat live {}", live_path.display()));
            }
        };
        let verdict = match live_size {
            None => BakVerdict::LiveMissing,
            Some(live) if live < bak_size => BakVerdict::LiveShrunk,
            Some(_) => BakVerdict::LiveOk,
        };
        out.push(BakReport {
            bak_path: path,
            bak_size,
            live_path,
            live_size,
            verdict,
        });
    }
    Ok(())
}

fn strip_bak_suffix(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(stripped) = s.strip_suffix(".bak") {
        return PathBuf::from(stripped);
    }
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn shrink_safe_write_creates_bak_when_new_content_is_shorter() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("freedom.yaml");
        std::fs::write(&target, b"operator_id: alice\nlanguage: de\nrole: dev\n").unwrap();

        let bak_written = shrink_safe_write(&target, b"operator_id: alice\n").unwrap();
        assert!(bak_written, "shrink must produce a bak");

        let bak = bak_path(&target);
        assert!(bak.exists());
        let bak_body = std::fs::read_to_string(&bak).unwrap();
        assert!(
            bak_body.contains("language: de"),
            "bak preserves pre-shrink state"
        );

        let live = std::fs::read_to_string(&target).unwrap();
        assert_eq!(live, "operator_id: alice\n");
    }

    #[test]
    fn shrink_safe_write_skips_bak_when_new_content_is_same_size() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("config.yaml");
        std::fs::write(&target, b"abc123").unwrap();
        let bak_written = shrink_safe_write(&target, b"xyz456").unwrap();
        assert!(!bak_written, "same-size write skips bak");
        assert!(!bak_path(&target).exists());
    }

    #[test]
    fn shrink_safe_write_skips_bak_when_new_content_grows_the_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("growing.txt");
        std::fs::write(&target, b"small").unwrap();
        let bak_written = shrink_safe_write(&target, b"much bigger content here").unwrap();
        assert!(!bak_written, "growth path must not bak");
        assert!(!bak_path(&target).exists());
    }

    #[test]
    fn shrink_safe_write_fresh_file_skips_bak() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("fresh.txt");
        let bak_written = shrink_safe_write(&target, b"first-write").unwrap();
        assert!(!bak_written, "no pre-existing file → nothing to bak");
        assert!(!bak_path(&target).exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "first-write");
    }

    #[test]
    fn bak_path_appends_dot_bak_to_full_filename() {
        // Pin the canonical bak naming so R-06 and shrink_safe_write
        // agree.
        let p = Path::new("/home/user/.neoth/freedom.yaml");
        assert_eq!(
            bak_path(p),
            PathBuf::from("/home/user/.neoth/freedom.yaml.bak")
        );
    }

    #[test]
    fn scan_returns_empty_for_missing_home() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("never-existed");
        let reports = scan_for_baks(&absent).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn scan_returns_empty_when_no_bak_files_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml"), b"x").unwrap();
        std::fs::write(dir.path().join("views.db"), b"sqlite").unwrap();
        let reports = scan_for_baks(dir.path()).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn scan_pairs_bak_with_live_file_and_classifies_verdicts() {
        let dir = tempdir().unwrap();
        // Case A: live file is bigger than bak → LiveOk.
        std::fs::write(dir.path().join("a.yaml"), b"AAAAAAAA").unwrap();
        std::fs::write(dir.path().join("a.yaml.bak"), b"AA").unwrap();
        // Case B: live file is smaller than bak → LiveShrunk.
        std::fs::write(dir.path().join("b.yaml"), b"B").unwrap();
        std::fs::write(dir.path().join("b.yaml.bak"), b"BBBBBBBB").unwrap();
        // Case C: live file gone → LiveMissing.
        std::fs::write(dir.path().join("c.yaml.bak"), b"CCC").unwrap();

        let reports = scan_for_baks(dir.path()).unwrap();
        assert_eq!(reports.len(), 3);

        let a = reports
            .iter()
            .find(|r| r.live_path.ends_with("a.yaml"))
            .unwrap();
        assert_eq!(a.verdict, BakVerdict::LiveOk);
        assert_eq!(a.bak_size, 2);
        assert_eq!(a.live_size, Some(8));

        let b = reports
            .iter()
            .find(|r| r.live_path.ends_with("b.yaml"))
            .unwrap();
        assert_eq!(b.verdict, BakVerdict::LiveShrunk);
        assert_eq!(b.live_size, Some(1));

        let c = reports
            .iter()
            .find(|r| r.live_path.ends_with("c.yaml"))
            .unwrap();
        assert_eq!(c.verdict, BakVerdict::LiveMissing);
        assert_eq!(c.live_size, None);
    }

    #[test]
    fn scan_descends_one_subdirectory_for_wal_bak_files() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::write(dir.path().join("wal/000001.wal"), b"live").unwrap();
        std::fs::write(dir.path().join("wal/000001.wal.bak"), b"bak").unwrap();
        let reports = scan_for_baks(dir.path()).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].live_path.ends_with("000001.wal"));
    }

    #[test]
    fn scan_skips_torn_write_artifacts_like_tmp_bak() {
        // Defensive: a crash mid-atomic-write could leave
        // freedom.yaml.tmp.bak. Don't surface those as restore
        // candidates — they're partial writes, not real snapshots.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml.tmp.bak"), b"partial").unwrap();
        std::fs::write(dir.path().join("config.yaml.bak.tmp"), b"partial2").unwrap();
        let reports = scan_for_baks(dir.path()).unwrap();
        assert!(
            reports.is_empty(),
            "torn-write artifacts must not surface as baks"
        );
    }

    #[test]
    fn second_shrink_overwrites_the_bak_with_most_recent_pre_shrink_state() {
        // Doc contract: bak holds the MOST RECENT pre-shrink state.
        // First shrink writes the original; second shrink overwrites
        // with the post-first-shrink content.
        let dir = tempdir().unwrap();
        let target = dir.path().join("config.yaml");
        std::fs::write(&target, b"AAAAAAAAAAAAAAAAAAAA").unwrap();
        shrink_safe_write(&target, b"BBBBBBBBBB").unwrap();
        shrink_safe_write(&target, b"CCC").unwrap();
        let bak_body = std::fs::read(bak_path(&target)).unwrap();
        assert_eq!(
            bak_body, b"BBBBBBBBBB",
            "bak must reflect the most recent pre-shrink state (B), not the original A",
        );
    }
}
