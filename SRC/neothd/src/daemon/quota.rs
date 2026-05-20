//! Disk-quota guard — Phase 33c BS-4.
//!
//! Pre-write check: if `~/.neoth/` already exceeds the operator-configured
//! ceiling, refuse the next WAL write and emit `EVENT_TYPE_QUOTA_BREACHED`
//! (0xF0) as the LAST frame before the daemon stops accepting writes.
//!
//! The check runs at the daemon level (not inside the WAL writer hot path)
//! because measuring directory size costs ~one stat per file, which adds
//! up at every frame. v0.1: poll the size at daemon startup, on every
//! consolidation pass, and via `neoth status`.
//!
//! Default ceiling: **5 GiB**. Operators can raise it in `freedom.yaml`
//! once they understand the storage growth profile of their workload.

use std::path::Path;

/// Default ceiling = 5 GiB. Picked to cover ~12 months of single-operator
/// daily use at the observed growth rate while still fitting under the
/// "shouldn't surprise the operator" threshold.
pub const DEFAULT_CEILING_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Result of a quota check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaState {
    /// Plenty of headroom.
    Ok { used: u64, ceiling: u64 },
    /// Within 90% of the ceiling. Operator should know but writes still go
    /// through.
    Warn { used: u64, ceiling: u64 },
    /// At or above the ceiling. Writes must be rejected.
    Breached { used: u64, ceiling: u64 },
}

impl QuotaState {
    pub fn used(&self) -> u64 {
        match self {
            QuotaState::Ok { used, .. }
            | QuotaState::Warn { used, .. }
            | QuotaState::Breached { used, .. } => *used,
        }
    }
    pub fn ceiling(&self) -> u64 {
        match self {
            QuotaState::Ok { ceiling, .. }
            | QuotaState::Warn { ceiling, .. }
            | QuotaState::Breached { ceiling, .. } => *ceiling,
        }
    }
    pub fn is_breached(&self) -> bool {
        matches!(self, QuotaState::Breached { .. })
    }
    pub fn is_warn(&self) -> bool {
        matches!(self, QuotaState::Warn { .. })
    }
}

/// Walk `dir` recursively and sum every regular file's `len()`. Symlinks
/// are NOT followed (avoid the wal-segment-pointing-to-/dev/null trick
/// inflating the count). Permission errors on individual entries are
/// silently skipped — the goal is "good enough" footprint, not a forensic
/// audit.
pub fn measure_dir(dir: &Path) -> u64 {
    fn walk(dir: &Path) -> u64 {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut total = 0u64;
        for entry in rd.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                total += walk(&entry.path());
            } else if file_type.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        total
    }
    walk(dir)
}

/// Classify the directory's current footprint against `ceiling`. `Warn`
/// fires at ≥ 90%.
pub fn check_quota(used: u64, ceiling: u64) -> QuotaState {
    if ceiling == 0 {
        return QuotaState::Ok { used, ceiling };
    }
    if used >= ceiling {
        QuotaState::Breached { used, ceiling }
    } else if used * 10 >= ceiling * 9 {
        QuotaState::Warn { used, ceiling }
    } else {
        QuotaState::Ok { used, ceiling }
    }
}

/// One-shot helper: measure + classify in a single call.
pub fn snapshot_quota(dir: &Path, ceiling: u64) -> QuotaState {
    let used = measure_dir(dir);
    check_quota(used, ceiling)
}

/// Format a byte count as a human-readable string for log lines.
pub fn format_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if b >= GIB {
        format!("{:.2} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.2} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.2} KiB", b as f64 / KIB as f64)
    } else {
        format!("{b} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_dir_is_zero_bytes() {
        let dir = tempdir().unwrap();
        assert_eq!(measure_dir(dir.path()), 0);
    }

    #[test]
    fn measure_sums_files_recursively() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), vec![0u8; 100]).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("b.bin"), vec![0u8; 200]).unwrap();
        assert_eq!(measure_dir(dir.path()), 300);
    }

    #[test]
    fn classify_thresholds() {
        // Below 90% → Ok
        assert_eq!(
            check_quota(800, 1000),
            QuotaState::Ok {
                used: 800,
                ceiling: 1000
            }
        );
        // At 90% → Warn
        assert!(matches!(check_quota(900, 1000), QuotaState::Warn { .. }));
        // 95% → Warn
        assert!(matches!(check_quota(950, 1000), QuotaState::Warn { .. }));
        // At ceiling → Breached
        assert!(check_quota(1000, 1000).is_breached());
        // Over ceiling → Breached
        assert!(check_quota(1500, 1000).is_breached());
    }

    #[test]
    fn zero_ceiling_disables_check() {
        // Ceiling 0 = operator disabled the guard.
        let state = check_quota(99_999, 0);
        assert!(matches!(state, QuotaState::Ok { .. }));
    }

    #[test]
    fn snapshot_runs_end_to_end() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a"), vec![0u8; 500]).unwrap();
        let state = snapshot_quota(dir.path(), 1000);
        assert!(state.is_warn() || matches!(state, QuotaState::Ok { .. }));
        assert_eq!(state.used(), 500);
        assert_eq!(state.ceiling(), 1000);
    }

    #[test]
    fn format_bytes_picks_friendly_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.46 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MiB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GiB");
    }

    #[test]
    fn symlinks_are_not_followed() {
        #[cfg(unix)]
        {
            let dir = tempdir().unwrap();
            // Target outside the measured dir — would inflate if followed.
            let outer = tempdir().unwrap();
            std::fs::write(outer.path().join("big"), vec![0u8; 10_000]).unwrap();
            std::os::unix::fs::symlink(outer.path().join("big"), dir.path().join("link")).unwrap();
            // Symlink itself is not a file → contributes 0.
            assert_eq!(measure_dir(dir.path()), 0);
        }
    }
}
