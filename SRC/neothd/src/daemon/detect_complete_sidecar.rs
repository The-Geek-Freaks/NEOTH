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
//! Sibling pattern: [`crate::daemon::installer_audit_sidecar`] +
//! [`crate::daemon::credentials_import_sidecar`] +
//! [`crate::cluster::audit_sidecar`].

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::wal::payloads_w08::DetectCompletePayload;

/// Lexicographic prefix that identifies a detect-complete sidecar.
/// Anything else in the home dir is ignored.
const FILENAME_PREFIX: &str = "detect_complete_";

/// List every pending detect-complete sidecar in chronological order
/// (zero-padded `ts_unix` in the filename guarantees lexicographic
/// == chronological). Missing home dir → empty vec, NOT an error.
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, DetectCompletePayload)>> {
    if !home.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(home)
        .with_context(|| format!("read {}", home.display()))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| is_detect_complete_sidecar(p))
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match serde_json::from_str::<DetectCompletePayload>(&body) {
            Ok(v) => v,
            Err(_) => continue, // Malformed → skip + leave in place
        };
        out.push((path, parsed));
    }
    Ok(out)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → `Ok(false)`.
pub fn remove_sidecar(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

/// Compose the bytes the WAL writer appends as the `0xD5
/// DETECT_COMPLETE` frame payload. Re-serialises the payload so the
/// WAL frame is canonical (not affected by pretty-print or
/// field-order quirks of the disk file).
pub fn build_wal_frame_body(payload: &DetectCompletePayload) -> Vec<u8> {
    serde_json::to_vec(payload).unwrap_or_default()
}

fn is_detect_complete_sidecar(p: &Path) -> bool {
    if p.extension().and_then(|x| x.to_str()) != Some("json") {
        return false;
    }
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(FILENAME_PREFIX))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
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
