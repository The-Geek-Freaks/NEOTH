//! P-01.b (Session 22, 2026-05-23) — `BehaviouralProfile` persistence
//! primitives.
//!
//! The 5 [`super::estimators`] estimators are pure-fn — they take
//! `&[ObservedTurn]` + return a `BehaviouralProfile`. This module ships
//! the operator-facing disk surface so consumers can:
//!
//! - **Persist** the latest aggregate via [`persist_snapshot`] (atomic
//!   write, mode 0600 on unix, JSON-encoded).
//! - **Load** the most recent snapshot via [`load_snapshot`] (returns
//!   `None` when missing / corrupted / unreadable — every consumer
//!   degrades gracefully when the snapshot file is absent).
//! - **Aggregate + persist** in one call via [`aggregate_and_persist`]
//!   so the cron task that scans the WAL for samples can hand a
//!   `Vec<ObservedTurn>` in + get the snapshot dropped to disk.
//!
//! ## Why a separate file from the SQLite view
//!
//! The `idx_behavioural_profile` view (mentioned in
//! [`super::estimators::BehaviouralProfile`] doc) is the v0.2 home for
//! the snapshot — a SQLite-backed surface that downstream recall
//! queries can join against. For v0.1 ship-readiness, a JSON file at
//! `~/.neoth/profile/behavioural.json` is the minimum-viable persistent
//! state: every consumer (briefing gate, GUI profile panel, audit
//! dump) reads it with one `serde_json::from_slice` call, no migration
//! tooling required.
//!
//! When the view lands, swap the read/write impl behind the same
//! function shapes — call sites don't change.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::estimators::{BehaviouralProfile, ObservedTurn, estimate_all};

/// Canonical relative path under the operator's NEOTH home.
/// Pinned in a const so a future rename surfaces in the drift-guard
/// test below.
pub const SNAPSHOT_RELATIVE_PATH: &str = "profile/behavioural.json";

/// Absolute path to the snapshot file for a given operator home.
pub fn snapshot_path(home: &Path) -> PathBuf {
    home.join(SNAPSHOT_RELATIVE_PATH)
}

/// Atomic write of `profile` to `~/.neoth/profile/behavioural.json`.
/// Creates the parent directory if missing. Unix: mode 0600 via
/// `wal::permissions::write_mode_0600` (same primitive freedom.yaml
/// uses, so the operator's permission model stays uniform across
/// state files).
///
/// Errors propagate via anyhow with operator-readable context. The
/// caller (cron task / CLI) decides whether to surface them or log
/// + continue.
pub fn persist_snapshot(home: &Path, profile: &BehaviouralProfile) -> Result<()> {
    let path = snapshot_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for snapshot: {}", parent.display()))?;
    }
    let bytes =
        serde_json::to_vec_pretty(profile).context("serialise BehaviouralProfile as JSON")?;
    let tmp = path.with_extension("json.tmp");
    crate::config::credentials::write_mode_0600(&tmp, &bytes)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Load the most recent snapshot. Returns `None` when:
///   - the file doesn't exist (fresh install, cron task hasn't run)
///   - the file is empty (atomic-rename race window, vanishingly rare
///     but caught defensively)
///   - the JSON fails to parse (corrupted / schema drift between
///     daemon versions — caller treats as "no snapshot available"
///     rather than panicking)
///
/// Every consumer is expected to handle `None` as the "snapshot
/// unavailable" signal + degrade to a safe default. The briefing
/// gate, for example, falls back to "Skip" so missing snapshot
/// never produces a spurious proactive ping.
pub fn load_snapshot(home: &Path) -> Option<BehaviouralProfile> {
    let path = snapshot_path(home);
    let bytes = std::fs::read(&path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Aggregate samples + persist the resulting snapshot. Single-shot
/// pipeline the future P-01.b WAL-scan cron task will call after
/// converting RAW_TEXT events into `Vec<ObservedTurn>`.
pub fn aggregate_and_persist(home: &Path, samples: &[ObservedTurn]) -> Result<BehaviouralProfile> {
    let profile = estimate_all(samples);
    persist_snapshot(home, &profile)?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn turn(ts: i64, text: &str) -> ObservedTurn {
        ObservedTurn {
            ts_unix: ts,
            text: text.to_string(),
        }
    }

    #[test]
    fn snapshot_relative_path_drift_guard() {
        // Pin: a future move (e.g. into `~/.neoth/state/`) needs to
        // bump the SCHEMA_VERSION too + ship a one-time copier. The
        // drift guard ensures the rename surfaces here at test time.
        assert_eq!(SNAPSHOT_RELATIVE_PATH, "profile/behavioural.json");
    }

    #[test]
    fn snapshot_path_under_home() {
        let p = snapshot_path(Path::new("/tmp/foo"));
        let s = p.to_string_lossy();
        // Cross-platform — windows uses `\` separator.
        assert!(s.contains("profile") && s.contains("behavioural.json"));
    }

    #[test]
    fn load_snapshot_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let result = load_snapshot(dir.path());
        assert!(result.is_none(), "missing file must return None");
    }

    #[test]
    fn load_snapshot_returns_none_when_empty() {
        let dir = tempdir().unwrap();
        let path = snapshot_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"").unwrap();
        let result = load_snapshot(dir.path());
        assert!(result.is_none(), "empty file must return None");
    }

    #[test]
    fn load_snapshot_returns_none_for_corrupted_json() {
        let dir = tempdir().unwrap();
        let path = snapshot_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not valid json {{{").unwrap();
        let result = load_snapshot(dir.path());
        assert!(
            result.is_none(),
            "corrupted JSON must degrade to None, not panic"
        );
    }

    #[test]
    fn persist_then_load_round_trips_profile() {
        // Full pipeline contract pin: aggregate_and_persist → load_snapshot
        // surfaces the same BehaviouralProfile.
        let dir = tempdir().unwrap();
        let samples = vec![
            turn(1_700_000_000, "first turn"),
            turn(1_700_000_300, "second turn here"),
            turn(1_700_000_600, "third one — slightly longer"),
        ];
        let original = aggregate_and_persist(dir.path(), &samples).expect("persist");
        let loaded = load_snapshot(dir.path()).expect("load");
        assert_eq!(loaded, original);
    }

    #[test]
    fn persist_creates_parent_dir_when_missing() {
        // Operator-side: fresh install has no ~/.neoth/profile/ dir
        // yet. persist_snapshot must create it on the fly so the cron
        // task doesn't bail at first run.
        let dir = tempdir().unwrap();
        let nested = dir.path().join("never-existed");
        let samples = vec![turn(1_700_000_000, "hi")];
        let profile = aggregate_and_persist(&nested, &samples).expect("persist on fresh dir");
        let loaded = load_snapshot(&nested).expect("load after fresh persist");
        assert_eq!(loaded, profile);
    }

    #[test]
    fn persist_is_atomic_write_via_tmp_then_rename() {
        // Pin: persist writes through a `.json.tmp` sibling + atomic
        // rename. A concurrent reader during persist sees either the
        // OLD file or the NEW file, never a partial write.
        // Detection: the `.json.tmp` file must NOT remain after a
        // successful persist (rename cleans it up).
        let dir = tempdir().unwrap();
        let samples = vec![turn(1_700_000_000, "hi")];
        aggregate_and_persist(dir.path(), &samples).expect("persist");
        let tmp = snapshot_path(dir.path()).with_extension("json.tmp");
        assert!(
            !tmp.exists(),
            ".json.tmp must be renamed away, found: {}",
            tmp.display()
        );
    }

    #[test]
    fn persist_overwrites_existing_snapshot() {
        // Pin: re-running aggregate_and_persist replaces the prior
        // snapshot — operator's profile updates as new turns land.
        let dir = tempdir().unwrap();
        let first = aggregate_and_persist(dir.path(), &[turn(1, "a")]).unwrap();
        let second =
            aggregate_and_persist(dir.path(), &[turn(1, "a"), turn(2, "b"), turn(3, "c")]).unwrap();
        assert_ne!(first, second);
        let loaded = load_snapshot(dir.path()).unwrap();
        assert_eq!(loaded, second);
    }
}
