//! W-05d (Session 26): daemon-side ingester for the `installer_ran_*.json`
//! sidecars dropped by `cli::installer::write_installer_audit_sidecar`.
//!
//! Problem: `neoth installer apply --yes` runs in a short-lived CLI
//! process with no WAL writer. It serialises an [`InstallerRanPayload`]
//! to `~/.neoth/installer_ran_<ts_unix>.json` (Windows-safe atomic
//! rename). The long-lived `neoth serve` writer picks it up here on
//! its next poll tick, emits a `0x12 INSTALLER_RAN` WAL frame, and
//! removes the file.
//!
//! At-least-once semantics: a crash between WAL append + file remove
//! leaves the sidecar in place for the next tick. The WAL writer
//! dedupes by `event_id` so a re-emit is idempotent from the consumer
//! side. CLI side is append-only — the daemon owns the delete.
//!
//! Session 27 refactor: the `list_pending` / `remove_sidecar` /
//! `build_wal_frame_body` trio is now generic over [`SidecarPayload`].
//! This module keeps the typed wrappers so the `cli::serve` call
//! sites stay verbatim; the impl block is the only new code here.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::daemon::sidecar::SidecarPayload;
use crate::wal::payloads_w08::InstallerRanPayload;

impl SidecarPayload for InstallerRanPayload {
    const FILENAME_PREFIX: &'static str = "installer_ran_";
}

/// List every pending installer-audit sidecar in chronological order.
/// Thin typed wrapper around [`crate::daemon::sidecar::list_pending`].
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, InstallerRanPayload)>> {
    crate::daemon::sidecar::list_pending::<InstallerRanPayload>(home)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → `Ok(false)`.
pub use crate::daemon::sidecar::remove_sidecar;

/// Compose the bytes the WAL writer appends as the `0x12 INSTALLER_RAN`
/// frame payload.
pub fn build_wal_frame_body(payload: &InstallerRanPayload) -> Vec<u8> {
    crate::daemon::sidecar::build_wal_frame_body(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn sample_payload(ts_unix: u64) -> InstallerRanPayload {
        InstallerRanPayload {
            cli_name: "Docker.Docker".into(),
            version: "27.4.0".into(),
            login_state: "n/a".into(),
            ts_unix,
            dry_run: false,
            wizard_step: "cli_installer_apply".into(),
            pkg_mgr: "winget".into(),
        }
    }

    fn write_file(home: &Path, name: &str, body: &str) {
        fs::create_dir_all(home).unwrap();
        fs::write(home.join(name), body).unwrap();
    }

    #[test]
    fn list_pending_missing_home_returns_empty() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("never-existed");
        let listed = list_pending(&absent).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_pending_skips_non_installer_files() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "README.md", "ignore");
        write_file(dir.path(), "credentials_import_100.json", "{}");
        write_file(dir.path(), "installer_ran_99.txt", "not json extension");
        let listed = list_pending(dir.path()).unwrap();
        assert!(
            listed.is_empty(),
            "only installer_ran_*.json should match, got {} entries",
            listed.len()
        );
    }

    #[test]
    fn list_pending_rejects_malformed_json_and_preserves_evidence() {
        let dir = tempdir().unwrap();
        let malformed = dir.path().join("installer_ran_1.json");
        write_file(dir.path(), "installer_ran_1.json", "{not json");
        // Plus one valid file.
        let valid = serde_json::to_string(&sample_payload(2)).unwrap();
        let valid_path = dir.path().join("installer_ran_2.json");
        write_file(dir.path(), "installer_ran_2.json", &valid);
        let error = list_pending(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("installer_ran_1.json"),
            "the offending audit sidecar must be identified: {error:#}"
        );
        assert!(malformed.exists());
        assert!(valid_path.exists());
    }

    #[test]
    fn list_pending_sorts_lexicographically_by_filename() {
        let dir = tempdir().unwrap();
        // Zero-padded so lexicographic == numeric order.
        for ts in [100u64, 50, 200] {
            let payload = serde_json::to_string(&sample_payload(ts)).unwrap();
            write_file(
                dir.path(),
                &format!("installer_ran_{ts:020}.json"),
                &payload,
            );
        }
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].1.ts_unix, 50);
        assert_eq!(listed[1].1.ts_unix, 100);
        assert_eq!(listed[2].1.ts_unix, 200);
    }

    #[test]
    fn remove_sidecar_is_idempotent() {
        let dir = tempdir().unwrap();
        let payload = serde_json::to_string(&sample_payload(1)).unwrap();
        let path = dir.path().join("installer_ran_1.json");
        fs::write(&path, payload).unwrap();
        assert!(remove_sidecar(&path).unwrap());
        assert!(!remove_sidecar(&path).unwrap());
    }

    #[test]
    fn build_wal_frame_body_round_trips_payload() {
        let payload = sample_payload(1_700_000_000);
        let body = build_wal_frame_body(&payload);
        let parsed: InstallerRanPayload = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn list_pending_keeps_wal_format_round_trip() {
        // End-to-end: write_file → list_pending returns parsed
        // payload identical to what the CLI wrote. Drift-guards any
        // future field addition that forgot a #[serde(default)].
        let dir = tempdir().unwrap();
        let original = sample_payload(42);
        let json = serde_json::to_string(&original).unwrap();
        write_file(dir.path(), "installer_ran_42.json", &json);
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, original);
    }
}
