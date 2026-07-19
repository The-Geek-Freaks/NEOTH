//! C-05d (Session 26): daemon-side ingester for the
//! `credentials_import_*.json` sidecars dropped by `cli::init`'s
//! wizard step 6g (credential import flow).
//!
//! Problem: the wizard runs in a short-lived CLI process with no WAL
//! writer. The SC-17 redactor produces a
//! [`RedactedCredentialImportPayload`] (no plaintext secrets — only
//! per-source counts + entry-shape booleans) which the wizard
//! serialises to `~/.neoth/credentials_import_<ts_unix>.json` via
//! atomic `.tmp` + rename. The long-lived `neoth serve` writer picks
//! it up here on its next poll tick, emits a `0xD6 CREDENTIAL_IMPORT`
//! WAL frame, and removes the file.
//!
//! Privacy invariant: the sidecar carries the same redacted payload
//! the wizard built. This module does NOT touch raw secret material —
//! the redactor lives upstream and is the only path that ever saw
//! plaintext. A drift-guard test in `security::credential_redact`
//! pins that the redactor's output type has no secret-bearing
//! fields.
//!
//! Session 27 refactor: the filesystem helpers moved into the
//! generic [`crate::daemon::sidecar`] module. The typed wrappers
//! below keep the `cli::serve` call sites unchanged.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::daemon::sidecar::SidecarPayload;
use crate::security::credential_redact::RedactedCredentialImportPayload;

impl SidecarPayload for RedactedCredentialImportPayload {
    const FILENAME_PREFIX: &'static str = "credentials_import_";
}

/// List every pending credential-import sidecar in chronological
/// order. Thin typed wrapper around
/// [`crate::daemon::sidecar::list_pending`].
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, RedactedCredentialImportPayload)>> {
    crate::daemon::sidecar::list_pending::<RedactedCredentialImportPayload>(home)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → `Ok(false)`.
pub use crate::daemon::sidecar::remove_sidecar;

/// Compose the bytes the WAL writer appends as the `0xD6
/// CREDENTIAL_IMPORT` frame payload.
pub fn build_wal_frame_body(payload: &RedactedCredentialImportPayload) -> Vec<u8> {
    crate::daemon::sidecar::build_wal_frame_body(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn sample_payload() -> RedactedCredentialImportPayload {
        use crate::security::credential_redact::{
            CredentialImportRecord, ImportSource, redact_credential_import,
        };
        // Empty import is intentional — the audit frame fires
        // regardless of operator's chosen entry count and the
        // ingester must accept the 0-entries shape.
        let record = CredentialImportRecord {
            source: ImportSource::WizardPrompt,
            entries: Vec::new(),
            target_vault_id: "test".to_string(),
            ts_unix: 0,
        };
        redact_credential_import(&record)
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
    fn list_pending_skips_non_credentials_files() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "README.md", "ignore");
        write_file(dir.path(), "installer_ran_1.json", "{}");
        write_file(
            dir.path(),
            "credentials_import_99.txt",
            "not json extension",
        );
        let listed = list_pending(dir.path()).unwrap();
        assert!(
            listed.is_empty(),
            "only credentials_import_*.json should match, got {} entries",
            listed.len()
        );
    }

    #[test]
    fn list_pending_rejects_malformed_json_and_preserves_evidence() {
        let dir = tempdir().unwrap();
        let malformed = dir.path().join("credentials_import_1.json");
        write_file(dir.path(), "credentials_import_1.json", "{not json");
        // Plus one valid file.
        let valid = serde_json::to_string(&sample_payload()).unwrap();
        let valid_path = dir.path().join("credentials_import_2.json");
        write_file(dir.path(), "credentials_import_2.json", &valid);
        let error = list_pending(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("credentials_import_1.json"),
            "the offending audit sidecar must be identified: {error:#}"
        );
        assert!(malformed.exists());
        assert!(valid_path.exists());
    }

    #[test]
    fn list_pending_sorts_lexicographically_by_filename() {
        let dir = tempdir().unwrap();
        let payload = serde_json::to_string(&sample_payload()).unwrap();
        // Zero-padded so lexicographic == numeric order.
        for ts in [100u64, 50, 200] {
            write_file(
                dir.path(),
                &format!("credentials_import_{ts:020}.json"),
                &payload,
            );
        }
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 3);
        // Filenames must be returned in lexicographic order so the
        // ingester emits WAL frames in the same order operators
        // produced them.
        let names: Vec<&str> = listed
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(names[0].contains("00000000000000000050"));
        assert!(names[1].contains("00000000000000000100"));
        assert!(names[2].contains("00000000000000000200"));
    }

    #[test]
    fn remove_sidecar_is_idempotent() {
        let dir = tempdir().unwrap();
        let payload = serde_json::to_string(&sample_payload()).unwrap();
        let path = dir.path().join("credentials_import_1.json");
        fs::write(&path, payload).unwrap();
        assert!(remove_sidecar(&path).unwrap());
        assert!(!remove_sidecar(&path).unwrap());
    }

    #[test]
    fn build_wal_frame_body_round_trips_payload() {
        let payload = sample_payload();
        let body = build_wal_frame_body(&payload);
        let parsed: RedactedCredentialImportPayload = serde_json::from_slice(&body).unwrap();
        // We compare via serialisation rather than a derive PartialEq
        // we'd have to add to the payload struct — the redactor's
        // canonical comparison surface is the JSON round-trip.
        let original = serde_json::to_string(&payload).unwrap();
        let back = serde_json::to_string(&parsed).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn list_pending_does_not_panic_on_empty_payload() {
        // Drift-guard: an empty (0-entries) import still produces a
        // valid sidecar. The ingester must not skip it just because
        // the operator picked "nothing to import" — the WAL frame
        // records the audit event itself.
        let dir = tempdir().unwrap();
        let json = serde_json::to_string(&sample_payload()).unwrap();
        write_file(dir.path(), "credentials_import_42.json", &json);
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
    }
}
