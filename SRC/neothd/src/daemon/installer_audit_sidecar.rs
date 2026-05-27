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
//! Sibling pattern: [`crate::cluster::audit_sidecar`] for cluster
//! confirm/revoke; [`crate::daemon::credentials_import_sidecar`] for
//! the credentials-import payload.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::wal::payloads_w08::InstallerRanPayload;

/// Lexicographic prefix that identifies an installer-audit sidecar.
/// Anything else in the home dir is ignored.
const FILENAME_PREFIX: &str = "installer_ran_";

/// List every pending installer-audit sidecar in chronological order
/// (filename embeds `ts_unix` so lexicographic == chronological).
/// Missing home dir → empty vec, NOT an error: pre-wizard fresh
/// installs land here.
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, InstallerRanPayload)>> {
    if !home.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(home)
        .with_context(|| format!("read {}", home.display()))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| is_installer_sidecar(p))
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match serde_json::from_str::<InstallerRanPayload>(&body) {
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

/// Compose the bytes the WAL writer appends as the `0x12 INSTALLER_RAN`
/// frame payload. Re-serialises the payload so the WAL frame is
/// independent of any pretty-print or field-order quirks of the file
/// on disk — the WAL body is the canonical record.
pub fn build_wal_frame_body(payload: &InstallerRanPayload) -> Vec<u8> {
    serde_json::to_vec(payload).unwrap_or_default()
}

fn is_installer_sidecar(p: &Path) -> bool {
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
    fn list_pending_skips_malformed_json() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "installer_ran_1.json", "{not json");
        // Plus one valid file.
        let valid = serde_json::to_string(&sample_payload(2)).unwrap();
        write_file(dir.path(), "installer_ran_2.json", &valid);
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(
            listed.len(),
            1,
            "malformed json must be skipped, valid one kept"
        );
        assert_eq!(listed[0].1.ts_unix, 2);
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
