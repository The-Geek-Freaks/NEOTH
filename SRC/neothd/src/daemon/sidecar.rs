//! Generic raw-payload sidecar pattern (Session 27 trait extraction).
//!
//! Three modules in `daemon/` share an identical filesystem ingest
//! shape — a short-lived CLI process serialises a typed payload to
//! `~/.neoth/<prefix><ts_unix>.json`, the long-lived `neoth serve`
//! writer picks it up here on a 5s tick, appends a WAL frame, then
//! removes the file. At-least-once semantics: a crash between WAL
//! append + file remove leaves the sidecar in place for the next
//! tick; the WAL writer dedupes by event_id.
//!
//! Implementors (Session 26):
//! - [`crate::wal::payloads_w08::InstallerRanPayload`]
//!   → `daemon::installer_audit_sidecar` (W-05d, `0x12 INSTALLER_RAN`)
//! - [`crate::security::credential_redact::RedactedCredentialImportPayload`]
//!   → `daemon::credentials_import_sidecar` (C-05d, `0xD6 CREDENTIAL_IMPORT`)
//! - [`crate::wal::payloads_w08::DetectCompletePayload`]
//!   → `daemon::detect_complete_sidecar` (W-04 follow-up, `0xD5 DETECT_COMPLETE`)
//!
//! [`crate::cluster::audit_sidecar`] uses an ENVELOPE shape
//! (`kind + payload`) instead, so it doesn't fit this trait
//! cleanly. A future `KindedSidecarPayload` super-trait could
//! unify both surfaces; deferred until a fourth raw-payload
//! sidecar surfaces and the dual-shape pattern is clearly
//! load-bearing.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Marker trait for raw-payload sidecars. Implementors declare the
/// filename prefix that identifies their sidecars in `~/.neoth/`.
///
/// Inherits `Serialize + DeserializeOwned` so the generic helpers
/// can round-trip the payload to/from disk without per-type glue.
/// The WAL event-type byte is intentionally NOT part of the trait
/// because the caller (the ingester task in `cli::serve::run_serve`)
/// builds the frame header itself with a typed `EVENT_TYPE_*`
/// constant — keeping the byte out of the trait keeps the trait
/// concerned with filesystem shape only.
pub trait SidecarPayload: Serialize + DeserializeOwned {
    /// Lexicographic prefix unique to this payload type — for
    /// example `"installer_ran_"`, `"credentials_import_"`,
    /// `"detect_complete_"`. Files in the home dir that don't
    /// start with this prefix AND end in `.json` are ignored.
    const FILENAME_PREFIX: &'static str;
}

/// List every pending sidecar of type `T` in chronological order.
/// Implementors that zero-pad the `ts_unix` in the filename get
/// lexicographic == chronological for free.
///
/// Missing home dir → empty vec, NOT an error: pre-wizard fresh
/// installs land here. Malformed JSON / unreadable file → skip
/// and leave on disk for operator inspection rather than losing
/// the disk-side evidence.
pub fn list_pending<T: SidecarPayload>(home: &Path) -> Result<Vec<(PathBuf, T)>> {
    if !home.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(home)
        .with_context(|| format!("read {}", home.display()))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| is_sidecar_for::<T>(p))
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match serde_json::from_str::<T>(&body) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push((path, parsed));
    }
    Ok(out)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → `Ok(false)`. Not generic over `T`
/// because every sidecar deletes the same way; the trait isn't
/// load-bearing here.
pub fn remove_sidecar(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

/// Compose the bytes the WAL writer appends as the frame payload.
/// Re-serialises so the WAL frame is independent of any pretty-
/// print / field-order quirks of the disk file — the WAL body is
/// the canonical record.
pub fn build_wal_frame_body<T: SidecarPayload>(payload: &T) -> Vec<u8> {
    serde_json::to_vec(payload).unwrap_or_default()
}

fn is_sidecar_for<T: SidecarPayload>(p: &Path) -> bool {
    if p.extension().and_then(|x| x.to_str()) != Some("json") {
        return false;
    }
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(T::FILENAME_PREFIX))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tempfile::tempdir;

    /// In-module test payload — exercises the trait surface without
    /// coupling to any of the three real payloads, so a future
    /// change to `InstallerRanPayload` etc. can't quietly break the
    /// generic helpers.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Sample {
        ts: u64,
        label: String,
    }

    impl SidecarPayload for Sample {
        const FILENAME_PREFIX: &'static str = "sample_";
    }

    fn write(dir: &Path, name: &str, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), body).unwrap();
    }

    fn sample(ts: u64) -> Sample {
        Sample {
            ts,
            label: format!("entry-{ts}"),
        }
    }

    #[test]
    fn list_pending_missing_home_returns_empty() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("never-existed");
        let listed = list_pending::<Sample>(&absent).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_pending_filters_by_prefix_and_extension() {
        let dir = tempdir().unwrap();
        write(dir.path(), "README.md", "ignore");
        write(dir.path(), "other_prefix_1.json", "{}");
        write(dir.path(), "sample_99.txt", "wrong ext");
        let listed = list_pending::<Sample>(dir.path()).unwrap();
        assert!(
            listed.is_empty(),
            "only sample_*.json must match, got {} entries",
            listed.len()
        );
    }

    #[test]
    fn list_pending_skips_malformed_json_keeps_valid() {
        let dir = tempdir().unwrap();
        write(dir.path(), "sample_1.json", "{not json");
        let valid = serde_json::to_string(&sample(2)).unwrap();
        write(dir.path(), "sample_2.json", &valid);
        let listed = list_pending::<Sample>(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1.ts, 2);
    }

    #[test]
    fn list_pending_sorts_lexicographically() {
        let dir = tempdir().unwrap();
        for ts in [100u64, 50, 200] {
            let json = serde_json::to_string(&sample(ts)).unwrap();
            write(dir.path(), &format!("sample_{ts:020}.json"), &json);
        }
        let listed = list_pending::<Sample>(dir.path()).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].1.ts, 50);
        assert_eq!(listed[1].1.ts, 100);
        assert_eq!(listed[2].1.ts, 200);
    }

    #[test]
    fn remove_sidecar_is_idempotent() {
        let dir = tempdir().unwrap();
        let json = serde_json::to_string(&sample(1)).unwrap();
        let path = dir.path().join("sample_1.json");
        fs::write(&path, json).unwrap();
        assert!(remove_sidecar(&path).unwrap());
        assert!(!remove_sidecar(&path).unwrap(),);
    }

    #[test]
    fn build_wal_frame_body_round_trips() {
        let payload = sample(42);
        let body = build_wal_frame_body(&payload);
        let parsed: Sample = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn is_sidecar_for_rejects_other_prefixes() {
        // Drift guard: a future module that adds a typo'd prefix
        // would silently swallow files. Pin the rejection path.
        #[derive(Serialize, Deserialize)]
        struct Other;
        impl SidecarPayload for Other {
            const FILENAME_PREFIX: &'static str = "other_";
        }
        let dir = tempdir().unwrap();
        let other = dir.path().join("other_1.json");
        let sample_path = dir.path().join("sample_1.json");
        assert!(super::is_sidecar_for::<Sample>(&sample_path));
        assert!(!super::is_sidecar_for::<Sample>(&other));
        assert!(super::is_sidecar_for::<Other>(&other));
        assert!(!super::is_sidecar_for::<Other>(&sample_path));
    }
}
