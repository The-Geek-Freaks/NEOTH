//! ADV-01 — crash-recovery scan + apply path for `.cpt` files.
//!
//! On daemon startup, `scan_and_apply` walks the WAL directory for any
//! `.cpt` files left behind by the previous compaction process. For
//! each pair it computes HMAC, verifies via [`super::cpt_auth`], and:
//!
//! - **Verify OK** → atomically rename `.cpt` → `.bin`, delete the
//!   `.cpt.hmac` sidecar (the replacement `.bin` has no sidecar).
//! - **Verify FAIL** → quarantine `.cpt`/`.cpt.hmac` via
//!   [`super::cpt_format::quarantine_pair`] + emit a
//!   `EVENT_TYPE_COMPACTION_AUTH_FAILED` WAL frame so operators see
//!   the rejection in `neoth wal show`.
//!
//! Per SPEC §4.3 the auth check happens **before** any frame from the
//! `.cpt` enters the live segment chain — an attacker who pre-places
//! a crafted `.cpt` cannot inject `PROFILE_DELTA` or tombstone frames
//! into the recovered segment without forging the HMAC.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::cpt_auth::CompactionAuthenticator;
use super::cpt_format::{hmac_path_for, quarantine_pair, read_and_verify_cpt};
use super::error::WalError;
use super::events::EVENT_TYPE_COMPACTION_AUTH_FAILED;

/// Outcome of processing one `.cpt` candidate during recovery scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CptOutcome {
    /// HMAC verified — `.cpt` was renamed to `cpt_path.with_extension("")`
    /// (drops the `.cpt` suffix, leaving a fresh `.bin`).
    Applied { applied_to: PathBuf },
    /// HMAC failed — pair quarantined + audit-event emitted (when a
    /// writer handle was passed).
    Quarantined {
        cpt_path: PathBuf,
        quarantine_path: PathBuf,
        reason: String,
    },
}

/// Result aggregate for one full directory scan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub applied: Vec<PathBuf>,
    pub quarantined: Vec<PathBuf>,
}

impl ScanReport {
    pub fn total(&self) -> usize {
        self.applied.len() + self.quarantined.len()
    }
}

/// Walk `wal_dir` for every `*.cpt` file and apply-or-quarantine each
/// pair. Returns a report so the caller can log a startup summary
/// ("recovered 1 .cpt, quarantined 0").
///
/// On HMAC failure the function quarantines and continues — a single
/// poisoned `.cpt` should not abort startup, only its own segment.
///
/// `now_unix_fn` returns the wall-clock seconds used in
/// quarantine-suffix + audit-frame timestamps. Injected for tests.
pub fn scan_and_apply(
    wal_dir: &Path,
    auth: &CompactionAuthenticator,
    now_unix_fn: impl Fn() -> u64,
) -> Result<ScanReport> {
    let mut report = ScanReport::default();
    if !wal_dir.exists() {
        return Ok(report);
    }
    for entry in
        fs::read_dir(wal_dir).with_context(|| format!("read WAL dir {}", wal_dir.display()))?
    {
        let entry = entry.context("read WAL dir entry")?;
        let path = entry.path();
        if !is_cpt_candidate(&path) {
            continue;
        }
        match process_one(&path, auth, now_unix_fn()) {
            Ok(CptOutcome::Applied { applied_to }) => {
                tracing::info!(
                    from = %path.display(),
                    to = %applied_to.display(),
                    "ADV-01: applied verified .cpt to .bin"
                );
                report.applied.push(applied_to);
            }
            Ok(CptOutcome::Quarantined {
                cpt_path,
                quarantine_path,
                reason,
            }) => {
                tracing::warn!(
                    cpt = %cpt_path.display(),
                    quarantine = %quarantine_path.display(),
                    reason = %reason,
                    "ADV-01: rejected .cpt failed HMAC — quarantined"
                );
                report.quarantined.push(quarantine_path);
            }
            Err(e) => {
                tracing::error!(
                    cpt = %path.display(),
                    error = %e,
                    "ADV-01: scan_and_apply encountered I/O error — skipping this .cpt"
                );
            }
        }
    }
    Ok(report)
}

/// Build the payload bytes for a [`EVENT_TYPE_COMPACTION_AUTH_FAILED`]
/// frame. Returned as `Vec<u8>` ready for `WalWriterHandle::append`.
/// Public so callers wiring the audit-frame emit (which lives in the
/// daemon boot path, not here) can construct payloads without
/// re-implementing the schema.
pub fn auth_failed_payload(
    cpt_path: &Path,
    reason: &str,
    ts_unix: u64,
    quarantine_path: &Path,
) -> Vec<u8> {
    let value = serde_json::json!({
        "cpt_path": cpt_path.display().to_string(),
        "reason": reason,
        "ts_unix": ts_unix,
        "quarantine_path": quarantine_path.display().to_string(),
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| {
        // Fallback — must never starve the audit chain even if serde
        // fails (e.g. a path contains malformed UTF-16 surrogates).
        format!(
            "{{\"cpt_path\":\"{}\",\"reason\":\"{}\",\"ts_unix\":{}}}",
            cpt_path.display(),
            reason.replace('"', ""),
            ts_unix
        )
        .into_bytes()
    })
}

/// Sanity-check the WAL event code claim is wired through this module
/// so a future renumber that breaks ADV-01 surfaces as a compile error
/// + this constant becomes the single grep target.
pub const ADV01_AUTH_FAIL_EVENT: u8 = EVENT_TYPE_COMPACTION_AUTH_FAILED;

fn is_cpt_candidate(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("cpt"))
            .unwrap_or(false)
}

fn process_one(
    cpt_path: &Path,
    auth: &CompactionAuthenticator,
    ts_unix: u64,
) -> Result<CptOutcome> {
    match read_and_verify_cpt(cpt_path, auth) {
        Ok(_content) => {
            // Apply: rename .cpt -> .bin (atomic on POSIX + NTFS).
            // The .cpt content IS the new .bin segment — frames inside
            // are already in WAL wire format from the compactor.
            let target = strip_cpt_suffix(cpt_path);
            fs::rename(cpt_path, &target).with_context(|| {
                format!(
                    "atomic rename {} -> {}",
                    cpt_path.display(),
                    target.display()
                )
            })?;
            // .cpt.hmac no longer needed once .cpt becomes .bin.
            let hmac_path = hmac_path_for(cpt_path);
            if hmac_path.exists() {
                let _ = fs::remove_file(&hmac_path); // best-effort
            }
            Ok(CptOutcome::Applied { applied_to: target })
        }
        Err(WalError::CompactionAuthFailed { reason }) => {
            let quarantine = quarantine_pair(cpt_path, ts_unix)
                .with_context(|| format!("quarantine failed .cpt {}", cpt_path.display()))?;
            Ok(CptOutcome::Quarantined {
                cpt_path: cpt_path.to_path_buf(),
                quarantine_path: quarantine,
                reason,
            })
        }
        Err(other) => Err(anyhow::anyhow!(other)),
    }
}

/// `wal-00000017.bin.cpt` → `wal-00000017.bin`. Drops only the final
/// `.cpt` component; preserves the `.bin` extension that the segment
/// walker expects.
fn strip_cpt_suffix(cpt_path: &Path) -> PathBuf {
    let s = cpt_path.to_string_lossy();
    if let Some(stem) = s.strip_suffix(".cpt") {
        PathBuf::from(stem)
    } else {
        // Should not happen — `is_cpt_candidate` already filtered.
        cpt_path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::cpt_format::write_cpt_pair;
    use tempfile::tempdir;

    fn fixture_auth() -> CompactionAuthenticator {
        CompactionAuthenticator::from_master_key(&(0u8..32).collect::<Vec<u8>>())
    }

    #[test]
    fn event_code_pinned_to_0x51() {
        // Pin: events 0x40 (JOB_FIRED) and 0x18 (REFUSAL_REDIRECTED)
        // were both proposed in earlier drafts but ALREADY TAKEN at
        // the time ADV-01 landed. 0x51 is the first free slot adjacent
        // to RECOVERY_TRUNCATED (0x50) in the recovery band. If a
        // future event-code refactor moves this, a `neoth wal show`
        // operator with old segments still in their archive sees
        // misinterpreted frame types — keep this constant loud.
        assert_eq!(ADV01_AUTH_FAIL_EVENT, 0x51);
    }

    #[test]
    fn empty_dir_returns_empty_report() {
        let dir = tempdir().unwrap();
        let report = scan_and_apply(dir.path(), &fixture_auth(), || 0).unwrap();
        assert_eq!(report.total(), 0);
    }

    #[test]
    fn missing_dir_returns_empty_report() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let report = scan_and_apply(&missing, &fixture_auth(), || 0).unwrap();
        assert_eq!(report.total(), 0);
    }

    #[test]
    fn valid_cpt_is_applied_to_bin() {
        let dir = tempdir().unwrap();
        let cpt_path = dir.path().join("wal-00000001.bin.cpt");
        let bin_path = dir.path().join("wal-00000001.bin");
        let auth = fixture_auth();
        let content = b"compacted-segment-bytes";
        write_cpt_pair(&cpt_path, content, &auth).unwrap();

        let report = scan_and_apply(dir.path(), &auth, || 1_716_595_300).unwrap();
        assert_eq!(report.applied.len(), 1);
        assert_eq!(report.quarantined.len(), 0);
        assert_eq!(report.applied[0], bin_path);

        // .bin now exists with the cpt content.
        assert!(bin_path.exists());
        assert_eq!(fs::read(&bin_path).unwrap(), content);
        // .cpt + .cpt.hmac are gone (rename + delete).
        assert!(!cpt_path.exists());
        assert!(!hmac_path_for(&cpt_path).exists());
    }

    #[test]
    fn tampered_cpt_is_quarantined_not_applied() {
        let dir = tempdir().unwrap();
        let cpt_path = dir.path().join("wal-00000002.bin.cpt");
        let bin_path = dir.path().join("wal-00000002.bin");
        let auth = fixture_auth();
        write_cpt_pair(&cpt_path, b"legitimate", &auth).unwrap();

        // Attacker tampers with the .cpt after the legitimate write.
        let mut bytes = fs::read(&cpt_path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(&cpt_path, &bytes).unwrap();

        let report = scan_and_apply(dir.path(), &auth, || 1_716_595_400).unwrap();
        assert_eq!(report.applied.len(), 0);
        assert_eq!(report.quarantined.len(), 1);

        // .bin was NOT created — the recovery refused to apply the
        // tampered payload.
        assert!(!bin_path.exists(), "tampered .cpt must NOT become .bin");
        // .cpt was renamed to the quarantine path.
        assert!(!cpt_path.exists());
        let q = &report.quarantined[0];
        assert!(q.exists(), "quarantine path must exist after rename");
        assert!(q.to_string_lossy().contains(".rejected.1716595400"));
    }

    #[test]
    fn cpt_without_hmac_is_quarantined() {
        let dir = tempdir().unwrap();
        let cpt_path = dir.path().join("wal-00000003.bin.cpt");
        // Operator (or attacker) drops a .cpt with NO .hmac sidecar —
        // the pre-ADV-01 unauthenticated state.
        fs::write(&cpt_path, b"orphan").unwrap();

        let report = scan_and_apply(dir.path(), &fixture_auth(), || 1_716_595_500).unwrap();
        assert_eq!(report.applied.len(), 0);
        assert_eq!(report.quarantined.len(), 1);
    }

    #[test]
    fn pair_signed_with_different_key_is_quarantined() {
        let dir = tempdir().unwrap();
        let cpt_path = dir.path().join("wal-00000004.bin.cpt");
        let alice_master: Vec<u8> = (0u8..32).collect();
        let alice = CompactionAuthenticator::from_master_key(&alice_master);
        write_cpt_pair(&cpt_path, b"alice payload", &alice).unwrap();

        // Bob boots NEOTH with a different master key — Alice's
        // legitimate-from-her-POV .cpt fails Bob's HMAC.
        let bob_master: Vec<u8> = (64u8..96).collect();
        let bob = CompactionAuthenticator::from_master_key(&bob_master);

        let report = scan_and_apply(dir.path(), &bob, || 1_716_595_600).unwrap();
        assert_eq!(report.applied.len(), 0);
        assert_eq!(report.quarantined.len(), 1);
    }

    #[test]
    fn scan_skips_non_cpt_files() {
        let dir = tempdir().unwrap();
        // Various non-targets that the scan MUST ignore.
        fs::write(dir.path().join("wal-00000005.bin"), b"sealed segment").unwrap();
        fs::write(dir.path().join("hmac.key"), b"key bytes").unwrap();
        fs::write(dir.path().join("WAL_SEQ"), b"5").unwrap();
        fs::write(dir.path().join("scratch.tmp"), b"junk").unwrap();

        let report = scan_and_apply(dir.path(), &fixture_auth(), || 0).unwrap();
        assert_eq!(report.total(), 0);

        // Files MUST still exist after scan.
        assert!(dir.path().join("wal-00000005.bin").exists());
        assert!(dir.path().join("hmac.key").exists());
    }

    #[test]
    fn auth_failed_payload_is_valid_json_with_expected_keys() {
        let payload = auth_failed_payload(
            Path::new("/tmp/wal/wal-00000007.bin.cpt"),
            "hmac mismatch",
            1_716_595_700,
            Path::new("/tmp/wal/wal-00000007.bin.cpt.rejected.1716595700"),
        );
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            v.get("reason").and_then(|x| x.as_str()),
            Some("hmac mismatch")
        );
        assert_eq!(
            v.get("ts_unix").and_then(|x| x.as_u64()),
            Some(1_716_595_700)
        );
        assert!(
            v.get("cpt_path")
                .and_then(|x| x.as_str())
                .unwrap()
                .contains("wal-00000007")
        );
        assert!(v.get("quarantine_path").is_some());
    }

    #[test]
    fn mixed_dir_with_one_valid_and_one_tampered_yields_one_of_each() {
        let dir = tempdir().unwrap();
        let auth = fixture_auth();

        let good = dir.path().join("wal-00000010.bin.cpt");
        write_cpt_pair(&good, b"good payload", &auth).unwrap();

        let bad = dir.path().join("wal-00000011.bin.cpt");
        write_cpt_pair(&bad, b"original", &auth).unwrap();
        let mut tamper = fs::read(&bad).unwrap();
        tamper[0] ^= 0xFF;
        fs::write(&bad, &tamper).unwrap();

        let report = scan_and_apply(dir.path(), &auth, || 1_716_595_800).unwrap();
        assert_eq!(report.applied.len(), 1);
        assert_eq!(report.quarantined.len(), 1);
        // The good one became .bin, the bad one is quarantined +
        // its .bin was never created.
        assert!(dir.path().join("wal-00000010.bin").exists());
        assert!(!dir.path().join("wal-00000011.bin").exists());
    }

    #[test]
    fn strip_cpt_suffix_only_removes_final_dot_cpt() {
        let p = PathBuf::from("/tmp/wal/wal-00000020.bin.cpt");
        let s = strip_cpt_suffix(&p);
        assert_eq!(s.to_string_lossy(), "/tmp/wal/wal-00000020.bin");
    }
}
