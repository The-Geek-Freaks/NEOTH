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
//! Sibling pattern: [`crate::cluster::audit_sidecar`] for cluster
//! confirm/revoke; [`crate::daemon::installer_audit_sidecar`] for
//! installer-run audits.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::security::credential_redact::RedactedCredentialImportPayload;

/// Lexicographic prefix that identifies a credential-import sidecar.
/// Anything else in the home dir is ignored.
const FILENAME_PREFIX: &str = "credentials_import_";

/// List every pending credential-import sidecar in chronological
/// order (filename embeds `ts_unix` so lexicographic == chronological
/// when callers pad the timestamp consistently). Missing home dir →
/// empty vec, NOT an error: pre-wizard fresh installs land here.
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, RedactedCredentialImportPayload)>> {
    if !home.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(home)
        .with_context(|| format!("read {}", home.display()))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| is_credentials_sidecar(p))
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match serde_json::from_str::<RedactedCredentialImportPayload>(&body) {
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

/// Compose the bytes the WAL writer appends as the `0xD6
/// CREDENTIAL_IMPORT` frame payload. Re-serialises so the WAL frame
/// is independent of any pretty-print or field-order quirks of the
/// file on disk — the WAL body is the canonical record.
pub fn build_wal_frame_body(payload: &RedactedCredentialImportPayload) -> Vec<u8> {
    serde_json::to_vec(payload).unwrap_or_default()
}

fn is_credentials_sidecar(p: &Path) -> bool {
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
    fn list_pending_skips_malformed_json() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "credentials_import_1.json", "{not json");
        // Plus one valid file.
        let valid = serde_json::to_string(&sample_payload()).unwrap();
        write_file(dir.path(), "credentials_import_2.json", &valid);
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(
            listed.len(),
            1,
            "malformed json must be skipped, valid one kept"
        );
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
