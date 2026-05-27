//! W-04 follow-up (Session 26): daemon-side ingester for the
//! `detect_complete_*.json` sidecars dropped by `cli::init::
//! step1b_detect_environment`.
//!
//! Problem: the wizard probes the operator's environment (docker,
//! npm, ffmpeg, gpu, …) and produces a [`DetectCompletePayload`]
//! describing what it found. The audit-trail event `0xD5
//! DETECT_COMPLETE` would have lived inside the wizard process, but
//! the wizard has no WAL writer (only the long-lived `neoth serve`
//! daemon does). Solution: the wizard writes the payload to
//! `~/.neoth/detect_complete_<ts_unix:020>.json` (zero-padded so
//! lexicographic == chronological), this loop polls every 5s,
//! emits the WAL frame, removes the file.
//!
//! At-least-once semantics: a crash between WAL append + file
//! remove leaves the sidecar for the next tick; the WAL writer
//! dedupes by event_id. The wizard side is append-only — the
//! daemon owns the delete.
//!
//! Session 27 refactor: filesystem helpers moved into the generic
//! [`crate::daemon::sidecar`] module. Typed wrappers below keep
//! the `cli::serve` call sites unchanged.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::daemon::sidecar::SidecarPayload;
use crate::wal::payloads_w08::DetectCompletePayload;

impl SidecarPayload for DetectCompletePayload {
    const FILENAME_PREFIX: &'static str = "detect_complete_";
}

/// List every pending detect-complete sidecar in chronological order.
/// Thin typed wrapper around [`crate::daemon::sidecar::list_pending`].
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, DetectCompletePayload)>> {
    crate::daemon::sidecar::list_pending::<DetectCompletePayload>(home)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → `Ok(false)`.
pub use crate::daemon::sidecar::remove_sidecar;

/// Compose the bytes the WAL writer appends as the `0xD5
/// DETECT_COMPLETE` frame payload.
pub fn build_wal_frame_body(payload: &DetectCompletePayload) -> Vec<u8> {
    crate::daemon::sidecar::build_wal_frame_body(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn sample_payload(ts_unix: u64) -> DetectCompletePayload {
        DetectCompletePayload {
            probed_at_unix: ts_unix,
            docker_version: Some("27.4.0".into()),
            docker_compose_version: None,
            docker_compose_legacy_version: None,
            npm_version: Some("10.9.4".into()),
            node_version: Some("22.22.1".into()),
            git_version: None,
            ffmpeg_version: None,
            gpu_kind: None,
            gpu_vram_mib: None,
            gpu_vendor: None,
            gpu_name: None,
            disk_free_bytes: None,
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
    fn list_pending_skips_non_detect_files() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "README.md", "ignore");
        write_file(dir.path(), "installer_ran_1.json", "{}");
        write_file(dir.path(), "credentials_import_1.json", "{}");
        let listed = list_pending(dir.path()).unwrap();
        assert!(
            listed.is_empty(),
            "only detect_complete_*.json should match, got {} entries",
            listed.len()
        );
    }

    #[test]
    fn list_pending_skips_malformed_json() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "detect_complete_1.json", "{not json");
        let valid = serde_json::to_string(&sample_payload(2)).unwrap();
        write_file(dir.path(), "detect_complete_2.json", &valid);
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(
            listed.len(),
            1,
            "malformed json must be skipped, valid one kept"
        );
        assert_eq!(listed[0].1.probed_at_unix, 2);
    }

    #[test]
    fn list_pending_sorts_lexicographically_by_filename() {
        let dir = tempdir().unwrap();
        for ts in [100u64, 50, 200] {
            let payload = serde_json::to_string(&sample_payload(ts)).unwrap();
            write_file(
                dir.path(),
                &format!("detect_complete_{ts:020}.json"),
                &payload,
            );
        }
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].1.probed_at_unix, 50);
        assert_eq!(listed[1].1.probed_at_unix, 100);
        assert_eq!(listed[2].1.probed_at_unix, 200);
    }

    #[test]
    fn remove_sidecar_is_idempotent() {
        let dir = tempdir().unwrap();
        let payload = serde_json::to_string(&sample_payload(1)).unwrap();
        let path = dir.path().join("detect_complete_1.json");
        fs::write(&path, payload).unwrap();
        assert!(remove_sidecar(&path).unwrap());
        assert!(!remove_sidecar(&path).unwrap());
    }

    #[test]
    fn build_wal_frame_body_round_trips_payload() {
        let payload = sample_payload(1_700_000_000);
        let body = build_wal_frame_body(&payload);
        let parsed: DetectCompletePayload = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, payload);
    }
}
