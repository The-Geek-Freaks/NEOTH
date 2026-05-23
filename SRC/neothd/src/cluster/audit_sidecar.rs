//! Audit-frame sidecar — bridge between CLI-side cluster operations
//! and the running daemon's WAL writer.
//!
//! Problem: `neoth cluster confirm` / `revoke` run in a short-lived
//! CLI process that has no WAL writer of its own. Spawning one
//! would race the long-lived `neoth serve` writer for the segment
//! file. Solution: CLI drops a JSON sidecar at
//! `~/.neoth/pending_audit/cluster_<event>_<ts_unix>_<rand>.json`,
//! the daemon's serve loop ingests + appends to the WAL on its
//! next tick + removes the sidecar.
//!
//! WAL event codes consumed:
//!   - `EVENT_TYPE_CLUSTER_PEER_CONFIRMED` (0xE6)
//!   - `EVENT_TYPE_CLUSTER_PEER_REVOKED`   (0xE7)
//!
//! Sidecar files are append-only from the CLI side; the daemon
//! does the only delete. A crash mid-ingest leaves the file
//! behind for the next tick to retry — at-least-once semantics
//! are fine for an audit frame (the WAL writer dedupes by frame
//! hash anyway).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Sidecar dir under `home`.
pub fn sidecar_dir(home: &Path) -> PathBuf {
    home.join("pending_audit")
}

/// What kind of cluster event a sidecar carries. Determines the
/// WAL event code the ingester picks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterAuditKind {
    PeerConfirmed,
    PeerRevoked,
}

impl ClusterAuditKind {
    pub fn wal_event_type(self) -> u8 {
        match self {
            Self::PeerConfirmed => crate::wal::events::EVENT_TYPE_CLUSTER_PEER_CONFIRMED,
            Self::PeerRevoked => crate::wal::events::EVENT_TYPE_CLUSTER_PEER_REVOKED,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerConfirmed => "peer_confirmed",
            Self::PeerRevoked => "peer_revoked",
        }
    }
}

/// JSONL row shape. Caller fills the payload (different field set
/// per kind — confirm carries label+addr+via+autonomy, revoke
/// only carries pub_key+ts).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterAuditSidecar {
    pub kind: ClusterAuditKind,
    /// `pub_key_hex` of the affected peer. Mandatory for both kinds.
    pub pub_key_hex: String,
    /// Free-form JSON payload. Wrapped so the WAL ingester can
    /// pass it through to the audit frame without knowing the
    /// per-kind field shape — Phase 6 may add fields without
    /// breaking the ingester.
    pub payload: serde_json::Value,
    /// Unix seconds when the CLI wrote the sidecar.
    pub created_ts_unix: i64,
}

/// Write a sidecar atomically. Returns the path that was written
/// so callers can structured-log it.
pub fn write_sidecar(
    home: &Path,
    kind: ClusterAuditKind,
    pub_key_hex: &str,
    payload: serde_json::Value,
) -> Result<PathBuf> {
    let dir = sidecar_dir(home);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now = dur.as_secs() as i64;
    // Nano-precision timestamp in the filename so close-spaced
    // writes (operator typing fast, scripted confirm via for-
    // loop, our own test suite) preserve chronological order
    // under lexicographic sort. `as_nanos()` returns u128 — pad
    // to 38 digits so every filename sorts correctly.
    let nanos = dur.as_nanos();
    let name = format!("cluster_{}_{}_{:038}.json", kind.as_str(), now, nanos);
    let path = dir.join(&name);
    let body = ClusterAuditSidecar {
        kind,
        pub_key_hex: pub_key_hex.to_string(),
        payload,
        created_ts_unix: now,
    };
    let tmp = path.with_extension("json.tmp");
    let body_bytes = serde_json::to_vec(&body).context("serialise sidecar")?;
    fs::write(&tmp, &body_bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(path)
}

/// List every pending sidecar in lexicographic order (which
/// equals chronological order since the filename embeds the
/// unix timestamp). Daemon's serve loop calls this on each
/// tick + appends each one to the WAL + removes the file.
pub fn list_pending(home: &Path) -> Result<Vec<(PathBuf, ClusterAuditSidecar)>> {
    let dir = sidecar_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("cluster_"))
                    .unwrap_or(false)
        })
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match serde_json::from_str::<ClusterAuditSidecar>(&body) {
            Ok(v) => v,
            Err(_) => continue, // Malformed → leave in place, ingester skips
        };
        out.push((path, parsed));
    }
    Ok(out)
}

/// Remove a sidecar after the WAL writer accepted its frame.
/// Idempotent — missing file → Ok(false).
pub fn remove_sidecar(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

/// Compose the WAL frame body the ingester writes. Returns the
/// bytes — caller hands them to `writer.append(header, body)`.
pub fn build_wal_frame_body(sidecar: &ClusterAuditSidecar) -> Vec<u8> {
    let frame = serde_json::json!({
        "kind": sidecar.kind.as_str(),
        "pub_key_hex": sidecar.pub_key_hex,
        "payload": sidecar.payload,
        "ts_unix": sidecar.created_ts_unix,
    });
    serde_json::to_vec(&frame).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_list_roundtrip() {
        let dir = tempdir().unwrap();
        let payload = serde_json::json!({"label": "laptop", "addr": "192.0.2.1:4242"});
        let path = write_sidecar(
            dir.path(),
            ClusterAuditKind::PeerConfirmed,
            &"ab".repeat(32),
            payload.clone(),
        )
        .unwrap();
        assert!(path.exists());
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1.kind, ClusterAuditKind::PeerConfirmed);
        assert_eq!(listed[0].1.payload, payload);
    }

    #[test]
    fn write_atomic_no_tmp_leftover() {
        let dir = tempdir().unwrap();
        write_sidecar(
            dir.path(),
            ClusterAuditKind::PeerRevoked,
            &"cd".repeat(32),
            serde_json::json!({}),
        )
        .unwrap();
        let any_tmp = std::fs::read_dir(sidecar_dir(dir.path()))
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("tmp"));
        assert!(!any_tmp, "no .tmp file should be left after atomic write");
    }

    #[test]
    fn list_pending_missing_dir_returns_empty() {
        let dir = tempdir().unwrap();
        let listed = list_pending(dir.path()).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_pending_sorts_chronologically() {
        let dir = tempdir().unwrap();
        // Write three sidecars with strictly increasing timestamps
        // by sleeping 1s between each — chronological order in
        // the filename guarantees lexicographic sort matches.
        for i in 0..3 {
            write_sidecar(
                dir.path(),
                ClusterAuditKind::PeerConfirmed,
                &"ab".repeat(32),
                serde_json::json!({"seq": i}),
            )
            .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 3);
        // Each row's `seq` matches its position.
        for (i, (_, side)) in listed.iter().enumerate() {
            assert_eq!(
                side.payload.get("seq").and_then(|v| v.as_i64()),
                Some(i as i64)
            );
        }
    }

    #[test]
    fn list_pending_skips_malformed_json() {
        let dir = tempdir().unwrap();
        let sdir = sidecar_dir(dir.path());
        fs::create_dir_all(&sdir).unwrap();
        fs::write(sdir.join("cluster_peer_confirmed_1_aaaa.json"), "{not json").unwrap();
        // Plus one valid file.
        write_sidecar(
            dir.path(),
            ClusterAuditKind::PeerConfirmed,
            &"ab".repeat(32),
            serde_json::json!({"label": "ok"}),
        )
        .unwrap();
        let listed = list_pending(dir.path()).unwrap();
        assert_eq!(listed.len(), 1, "malformed json must be skipped");
    }

    #[test]
    fn list_pending_skips_non_cluster_files() {
        let dir = tempdir().unwrap();
        let sdir = sidecar_dir(dir.path());
        fs::create_dir_all(&sdir).unwrap();
        // Drop a non-cluster file in the sidecar dir.
        fs::write(sdir.join("README.md"), "ignore me").unwrap();
        fs::write(sdir.join("other_event_1.json"), "{}").unwrap();
        let listed = list_pending(dir.path()).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn remove_sidecar_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = write_sidecar(
            dir.path(),
            ClusterAuditKind::PeerConfirmed,
            &"ab".repeat(32),
            serde_json::json!({}),
        )
        .unwrap();
        assert!(remove_sidecar(&path).unwrap());
        assert!(!remove_sidecar(&path).unwrap());
    }

    #[test]
    fn wal_event_type_maps_to_correct_code() {
        assert_eq!(
            ClusterAuditKind::PeerConfirmed.wal_event_type(),
            crate::wal::events::EVENT_TYPE_CLUSTER_PEER_CONFIRMED
        );
        assert_eq!(
            ClusterAuditKind::PeerRevoked.wal_event_type(),
            crate::wal::events::EVENT_TYPE_CLUSTER_PEER_REVOKED
        );
    }

    #[test]
    fn build_wal_frame_body_carries_kind_and_payload() {
        let sidecar = ClusterAuditSidecar {
            kind: ClusterAuditKind::PeerConfirmed,
            pub_key_hex: "ab".repeat(32),
            payload: serde_json::json!({"label": "laptop"}),
            created_ts_unix: 1_700_000_000,
        };
        let body = build_wal_frame_body(&sidecar);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["kind"], "peer_confirmed");
        assert_eq!(parsed["payload"]["label"], "laptop");
        assert_eq!(parsed["ts_unix"], 1_700_000_000);
    }
}
