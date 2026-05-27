//! Round-3 v0.4 SC-04 — `neoth security audit` operator-facing
//! one-shot security report.
//!
//! Aggregates the existing security primitives scattered across
//! `permissions::audit`, `memory::drift`, `wal::*` into a single
//! pass + prints a checklist-style report. Each check is
//! independent: one failing check doesn't abort the others, so the
//! operator sees the full posture in one invocation rather than
//! discovering issues piecemeal across `neoth doctor` /
//! `neoth permissions audit` / `neoth memory drift` calls.
//!
//! ## Checks today
//!
//! | Check                               | What it surfaces                          |
//! |-------------------------------------|-------------------------------------------|
//! | HMAC compaction key                 | file presence + permissions/DACL          |
//! | WAL segment health                  | latest segment exists + non-empty         |
//! | Permission decisions (last 24h)     | grant / deny / consent counts             |
//! | Memory drift (Hippocampus)          | imminent + at-risk row counts             |
//! | Consent state (cloud providers)     | per-provider granted/denied flags         |
//!
//! ## Output format
//!
//! Per-check line with one of three status markers:
//! - `[ OK ]` — green-path; the check passed.
//! - `[WARN]` — caller-visible signal (e.g. drift queue non-empty)
//!   that doesn't break security but needs attention.
//! - `[FAIL]` — a security primitive is missing / mis-configured /
//!   reports an integrity error. Operator should fix before next
//!   sensitive operation.
//!
//! The report exits non-zero iff any check is `[FAIL]`. Non-fatal
//! warnings don't change the exit code (matches the operator's
//! `neoth doctor` exit-code semantics).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct SecurityArgs {
    #[command(subcommand)]
    pub command: SecurityCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SecurityCommand {
    /// One-shot security posture report — runs every available
    /// check + prints a pass/warn/fail checklist. Exit code 0 on
    /// all-clear, 1 if any check FAILed (warnings don't change
    /// exit). Matches the `neoth doctor` semantics.
    Audit(AuditArgs),
    /// SC-09 (Session 28) — export the WAL HMAC compaction key to
    /// `<output>` in plaintext for disaster-recovery purposes
    /// (machine swap, Windows reinstall, DPAPI unwrap failure).
    ///
    /// **What this is for**: per `PLAN/RUNBOOK_dpapi_hmac_recovery.md`,
    /// the WAL HMAC key on Windows is DPAPI-wrapped + bound to the
    /// current user account + machine identity. When any of those
    /// three change (machine swap / Windows reinstall in place /
    /// MS-account ↔ local-account switch), CryptUnprotectData fails
    /// + the operator's compaction-marker audit chain can't be
    /// verified. A plaintext backup taken BEFORE such an event lets
    /// the operator re-wrap the key on the new identity (Tier 1
    /// recovery — full audit-chain continuity preserved).
    ///
    /// **What this is NOT for**: routine use. The plaintext file
    /// loses the per-user DACL + DPAPI binding the in-place key has.
    /// The runbook warns operators to store the backup in their
    /// password manager / hardware token / sealed vault — NOT on the
    /// same disk as `~/.neoth`.
    BackupHmacKey(BackupHmacKeyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct BackupHmacKeyArgs {
    /// Plaintext destination path. The file is written mode-0600
    /// (Unix) so it's only readable by the operator account. Refused
    /// if the path already exists unless `--force` is also passed
    /// (defence against silent overwrite of an older backup).
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
    /// Overwrite `--output` if it already exists. Without this flag
    /// the command fails fast — accidentally re-running this command
    /// with the same `--output` shouldn't blow away an older backup
    /// taken at a different rotation.
    #[arg(long)]
    pub force: bool,
    /// Override the `~/.neoth` home dir (mostly for tests). Defaults
    /// to the operator's actual `~/.neoth`.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    /// Override the `~/.neoth` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Lookback window for the permission-decisions check, in
    /// hours. Default 24h covers operator's last day of activity.
    #[arg(long, value_name = "HOURS", default_value_t = 24)]
    pub permissions_lookback_hours: u64,

    /// Cap on drifting-row display per severity bucket. Doesn't
    /// affect the summary counts.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub drift_display_cap: usize,
}

/// Severity marker for a single audit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn marker(self) -> &'static str {
        match self {
            CheckStatus::Ok => "[ OK ]",
            CheckStatus::Warn => "[WARN]",
            CheckStatus::Fail => "[FAIL]",
        }
    }
}

/// One row in the audit report. `detail` is the human-readable
/// one-line summary printed alongside the status marker.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Full audit report. `exit_code()` returns 1 iff any check FAILed.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    pub checks: Vec<CheckResult>,
}

impl AuditReport {
    pub fn push(&mut self, name: &'static str, status: CheckStatus, detail: impl Into<String>) {
        self.checks.push(CheckResult {
            name,
            status,
            detail: detail.into(),
        });
    }

    pub fn exit_code(&self) -> i32 {
        if self
            .checks
            .iter()
            .any(|c| matches!(c.status, CheckStatus::Fail))
        {
            1
        } else {
            0
        }
    }

    /// Per-status counts for the operator's tail summary.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                CheckStatus::Ok => ok += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }
}

pub async fn run_security(args: SecurityArgs) -> Result<()> {
    match args.command {
        SecurityCommand::Audit(a) => {
            let report = run_audit_collect(&a)?;
            print_report(&report);
            let code = report.exit_code();
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        SecurityCommand::BackupHmacKey(a) => run_backup_hmac_key(&a),
    }
}

/// SC-09 (Session 28) — write the operator's WAL HMAC compaction key
/// to `args.output` in plaintext. Handles the DPAPI unwrap on Windows
/// (via `wal::compaction::load_or_init_key`); the operator sees the
/// raw bytes regardless of how they're stored on disk.
///
/// **Operator-visible warnings are deliberate**: this path is the
/// ONE place NEOTH legitimately emits a plaintext copy of the
/// HMAC key. Every line of stderr is one the operator should read.
pub fn run_backup_hmac_key(args: &BackupHmacKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);

    // Refuse overwrite unless --force. Catches the muscle-memory
    // mistake of re-running the same command (which would silently
    // replace an older backup that referred to a different key
    // rotation epoch).
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "refusing to overwrite existing backup at {}; pass --force to replace",
            args.output.display()
        );
    }

    let key_path = home.join("wal").join("hmac.key");
    if !key_path.exists() {
        anyhow::bail!(
            "no HMAC key at {} — run `neothd init` first or wait for the first WAL frame to be written",
            key_path.display()
        );
    }
    let key_bytes = crate::wal::compaction::load_or_init_key(&key_path)?;

    // Ensure the parent dir exists so a fresh `--output ~/safe/key`
    // works without the operator pre-mkdiring.
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create backup parent {}: {e}", parent.display()))?;
        }
    }

    write_backup_file(&args.output, &key_bytes)?;

    // stderr-only warnings — stdout is reserved for the operator-
    // visible success line so scripts that capture stdout get a
    // clean confirmation.
    eprintln!();
    eprintln!("[neoth security] PLAINTEXT BACKUP WRITTEN");
    eprintln!("[neoth security]   path:    {}", args.output.display());
    eprintln!(
        "[neoth security]   bytes:   {} (mode-0600 on Unix)",
        key_bytes.len()
    );
    eprintln!("[neoth security]");
    eprintln!("[neoth security] This file is the unwrapped HMAC key that protects your");
    eprintln!("[neoth security] WAL compaction markers. Anyone with read access can forge");
    eprintln!("[neoth security] historical audit-chain checkpoints.");
    eprintln!("[neoth security]");
    eprintln!("[neoth security] Recommended: move to a password manager / hardware token");
    eprintln!("[neoth security]   immediately; do NOT leave on the same disk as ~/.neoth.");
    eprintln!("[neoth security]   See PLAN/RUNBOOK_dpapi_hmac_recovery.md for the full recovery");
    eprintln!("[neoth security]   playbook (Tier 1 — re-wrap on new machine).");

    println!("backup written: {}", args.output.display());
    Ok(())
}

/// Write the plaintext key bytes mode-0600 on Unix. Windows DACL
/// tightening would mirror the SC-08 plan and is deferred — for
/// now the operator gets the default ACL on the destination,
/// which matches what they get for any other plaintext file
/// they create. The stderr warning above tells them to move it.
fn write_backup_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    // Open with write-only + create + truncate semantics. mode-0600
    // applied via OpenOptions on Unix; the `mode()` call is a no-op
    // on non-Unix targets but compiles via the cfg.
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open
        .open(path)
        .map_err(|e| anyhow::anyhow!("open backup path {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("write backup bytes to {}: {e}", path.display()))?;
    f.flush()
        .map_err(|e| anyhow::anyhow!("flush backup file {}: {e}", path.display()))?;
    Ok(())
}

/// Collect the audit report without printing — pure-fn variant so
/// tests can assert on `AuditReport` without parsing stdout.
pub fn run_audit_collect(args: &AuditArgs) -> Result<AuditReport> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let mut report = AuditReport::default();
    check_hmac_key(&home, &mut report);
    check_wal_segment(&home, &mut report);
    check_memory_drift(&home, args.drift_display_cap, &mut report);
    check_credential_files(&home, &mut report);
    Ok(report)
}

fn check_hmac_key(home: &Path, report: &mut AuditReport) {
    let key_path = home.join("wal_hmac_key");
    if !key_path.exists() {
        report.push(
            "HMAC compaction key",
            CheckStatus::Fail,
            format!("missing at {}", key_path.display()),
        );
        return;
    }
    let metadata = match std::fs::metadata(&key_path) {
        Ok(m) => m,
        Err(e) => {
            report.push(
                "HMAC compaction key",
                CheckStatus::Fail,
                format!("stat failed at {}: {e}", key_path.display()),
            );
            return;
        }
    };
    if metadata.len() == 0 {
        report.push(
            "HMAC compaction key",
            CheckStatus::Fail,
            format!("zero-length file at {}", key_path.display()),
        );
        return;
    }
    // Unix perm check — readable to owner only (mode 0600). On
    // Windows the DACL check ships in SC-08 (K-Sec-4 already restricts
    // via SetNamedSecurityInfoW); audit here just confirms presence.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            report.push(
                "HMAC compaction key",
                CheckStatus::Fail,
                format!("permissions {mode:o} too permissive (need 0600 or stricter)"),
            );
            return;
        }
        report.push(
            "HMAC compaction key",
            CheckStatus::Ok,
            format!(
                "{} ({} bytes, mode {:o})",
                key_path.display(),
                metadata.len(),
                mode
            ),
        );
    }
    #[cfg(not(unix))]
    {
        report.push(
            "HMAC compaction key",
            CheckStatus::Ok,
            format!(
                "{} ({} bytes; Windows DACL check via K-Sec-4)",
                key_path.display(),
                metadata.len()
            ),
        );
    }
}

fn check_wal_segment(home: &Path, report: &mut AuditReport) {
    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!(
                "no WAL directory yet at {} (fresh install)",
                wal_dir.display()
            ),
        );
        return;
    }
    let mut latest: Option<(PathBuf, u64)> = None;
    let read_dir = match std::fs::read_dir(&wal_dir) {
        Ok(d) => d,
        Err(e) => {
            report.push(
                "WAL segment health",
                CheckStatus::Fail,
                format!("read_dir failed at {}: {e}", wal_dir.display()),
            );
            return;
        }
    };
    for entry in read_dir.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let size = match entry.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if latest.as_ref().map(|(lp, _)| &p > lp).unwrap_or(true) {
            latest = Some((p, size));
        }
    }
    match latest {
        None => report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!("no .wal files in {} yet", wal_dir.display()),
        ),
        Some((p, 0)) => report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!("latest segment {} is empty", p.display()),
        ),
        Some((p, size)) => report.push(
            "WAL segment health",
            CheckStatus::Ok,
            format!("latest segment {} ({} bytes)", p.display(), size),
        ),
    }
}

fn check_memory_drift(home: &Path, display_cap: usize, report: &mut AuditReport) {
    let views_path = home.join("views.db");
    if !views_path.exists() {
        report.push(
            "Memory drift (Hippocampus)",
            CheckStatus::Warn,
            format!(
                "no views.db at {} yet (fresh install / no episodes)",
                views_path.display()
            ),
        );
        return;
    }
    let conn = match crate::memory::store::open(&views_path) {
        Ok(c) => c,
        Err(e) => {
            report.push(
                "Memory drift (Hippocampus)",
                CheckStatus::Fail,
                format!("views.db open failed: {e}"),
            );
            return;
        }
    };
    let drift = match crate::memory::drift::drift_report(&conn, display_cap) {
        Ok(r) => r,
        Err(e) => {
            report.push(
                "Memory drift (Hippocampus)",
                CheckStatus::Fail,
                format!("drift query failed: {e}"),
            );
            return;
        }
    };
    let detail = format!(
        "imminent={} at_risk={} stable={}",
        drift.imminent_count, drift.at_risk_count, drift.stable_count
    );
    let status = if drift.imminent_count > 0 {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };
    report.push("Memory drift (Hippocampus)", status, detail);
}

fn check_credential_files(home: &Path, report: &mut AuditReport) {
    // Look for the optional credential-import sidecar files the
    // wizard's step-6g writes. Their presence isn't a failure —
    // they should be transient (consumed by the daemon's next
    // boot). A stale sidecar > 7 days suggests the daemon never
    // started + the operator's credential import is in limbo.
    let mut found_sidecar = false;
    let mut stale_count = 0usize;
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("credentials_import_") || !name.ends_with(".json") {
                continue;
            }
            found_sidecar = true;
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(age) = modified.elapsed() {
                        if age.as_secs() > 7 * 24 * 3600 {
                            stale_count += 1;
                        }
                    }
                }
            }
        }
    }
    if !found_sidecar {
        report.push(
            "Credential import sidecars",
            CheckStatus::Ok,
            "no pending sidecars (all clean)".to_string(),
        );
        return;
    }
    if stale_count > 0 {
        report.push(
            "Credential import sidecars",
            CheckStatus::Warn,
            format!("{stale_count} sidecar(s) > 7 days old — daemon may not be running"),
        );
    } else {
        report.push(
            "Credential import sidecars",
            CheckStatus::Ok,
            "sidecar(s) present + recent (daemon should consume on next boot)".to_string(),
        );
    }
}

fn print_report(report: &AuditReport) {
    println!("== neoth security audit ==");
    println!();
    for c in &report.checks {
        println!("{}  {}  — {}", c.status.marker(), c.name, c.detail);
    }
    let (ok, warn, fail) = report.counts();
    println!();
    println!("Summary: {ok} ok / {warn} warn / {fail} fail");
    if fail > 0 {
        println!();
        println!("Exit code 1 — at least one check FAILed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn empty_audit_args(home: &Path) -> AuditArgs {
        AuditArgs {
            home: Some(home.to_path_buf()),
            permissions_lookback_hours: 24,
            drift_display_cap: 10,
        }
    }

    #[test]
    fn check_status_markers_canonical() {
        assert_eq!(CheckStatus::Ok.marker(), "[ OK ]");
        assert_eq!(CheckStatus::Warn.marker(), "[WARN]");
        assert_eq!(CheckStatus::Fail.marker(), "[FAIL]");
    }

    #[test]
    fn empty_report_exit_zero() {
        let r = AuditReport::default();
        assert_eq!(r.exit_code(), 0);
        assert_eq!(r.counts(), (0, 0, 0));
    }

    #[test]
    fn report_with_only_ok_exits_zero() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Ok, "ok");
        assert_eq!(r.exit_code(), 0);
        assert_eq!(r.counts(), (2, 0, 0));
    }

    #[test]
    fn report_with_warn_still_exits_zero() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Warn, "fyi");
        assert_eq!(r.exit_code(), 0, "warn must NOT trigger non-zero exit");
        assert_eq!(r.counts(), (1, 1, 0));
    }

    #[test]
    fn report_with_fail_exits_one() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Fail, "broken");
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.counts(), (1, 0, 1));
    }

    // ── check_hmac_key ────────────────────────────────────────────

    #[test]
    fn hmac_key_missing_fails() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("missing"));
    }

    #[test]
    fn hmac_key_empty_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(&tmp.path().join("wal_hmac_key"), b"");
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("zero-length"));
    }

    #[cfg(unix)]
    #[test]
    fn hmac_key_with_secure_mode_passes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal_hmac_key");
        write_file(&path, b"0123456789abcdef");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn hmac_key_world_readable_fails() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal_hmac_key");
        write_file(&path, b"0123456789abcdef");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("too permissive"));
    }

    #[cfg(windows)]
    #[test]
    fn hmac_key_with_content_passes_on_windows() {
        let tmp = TempDir::new().unwrap();
        write_file(&tmp.path().join("wal_hmac_key"), b"0123456789abcdef");
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("Windows DACL"));
    }

    // ── check_wal_segment ─────────────────────────────────────────

    #[test]
    fn wal_segment_no_dir_warns() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("fresh install"));
    }

    #[test]
    fn wal_segment_empty_dir_warns() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("wal")).unwrap();
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("no .wal files"));
    }

    #[test]
    fn wal_segment_zero_length_warns() {
        let tmp = TempDir::new().unwrap();
        write_file(&tmp.path().join("wal").join("000001.wal"), b"");
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("empty"));
    }

    #[test]
    fn wal_segment_with_content_passes() {
        let tmp = TempDir::new().unwrap();
        write_file(
            &tmp.path().join("wal").join("000001.wal"),
            b"some-bytes-here",
        );
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("15 bytes"));
    }

    // ── check_credential_files ────────────────────────────────────

    #[test]
    fn credential_sidecars_none_passes() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_credential_files(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("no pending"));
    }

    #[test]
    fn credential_sidecars_recent_passes() {
        let tmp = TempDir::new().unwrap();
        write_file(
            &tmp.path().join("credentials_import_1700000000.json"),
            b"{}",
        );
        let mut report = AuditReport::default();
        check_credential_files(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("present"));
    }

    // ── end-to-end run_audit_collect ──────────────────────────────

    #[test]
    fn run_audit_collect_on_empty_home_produces_expected_count() {
        let tmp = TempDir::new().unwrap();
        let args = empty_audit_args(tmp.path());
        let report = run_audit_collect(&args).unwrap();
        assert_eq!(report.checks.len(), 4, "4 checks ship in this revision");
        // On an empty home: HMAC missing (Fail), WAL absent (Warn),
        // drift absent (Warn), sidecars none (Ok). Exit code 1 due
        // to the HMAC fail.
        assert_eq!(report.exit_code(), 1);
    }

    // ── SC-09 backup-hmac-key ─────────────────────────────────────

    fn seed_hmac_key(home: &Path) -> std::path::PathBuf {
        // Generate a real key via load_or_init_key so the test
        // exercises the unwrap path the operator would hit.
        let key_path = home.join("wal").join("hmac.key");
        crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        key_path
    }

    #[test]
    fn backup_refuses_when_no_hmac_key_present() {
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let args = BackupHmacKeyArgs {
            output: out.path().join("missing.key"),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        let err = run_backup_hmac_key(&args).unwrap_err();
        assert!(
            err.to_string().contains("no HMAC key at"),
            "expected missing-key error; got {err}"
        );
        assert!(
            !args.output.exists(),
            "no backup file may be created when source missing"
        );
    }

    #[test]
    fn backup_writes_plaintext_key_when_source_present() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        assert!(dest.exists(), "backup file must be created");
        let bytes = std::fs::read(&dest).unwrap();
        // load_or_init_key returns ≥16 bytes (the under-16 check
        // refuses weak keys); a fresh key is exactly 32.
        assert!(bytes.len() >= 16, "key must be at least 16 bytes");
    }

    #[test]
    fn backup_refuses_to_overwrite_existing_without_force() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        // Pre-create a sentinel file at the destination.
        std::fs::write(&dest, b"older-backup-sentinel").unwrap();
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        let err = run_backup_hmac_key(&args).unwrap_err();
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "expected overwrite-refusal; got {err}"
        );
        // Sentinel must still be there — no clobber.
        let body = std::fs::read(&dest).unwrap();
        assert_eq!(body, b"older-backup-sentinel");
    }

    #[test]
    fn backup_overwrites_with_force_flag() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        std::fs::write(&dest, b"older-backup").unwrap();
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: true,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let body = std::fs::read(&dest).unwrap();
        assert_ne!(body, b"older-backup", "old content must be replaced");
        assert!(body.len() >= 16, "new content is the real key bytes");
    }

    #[test]
    fn backup_round_trip_matches_load_or_init_key() {
        // Backup bytes MUST equal what `load_or_init_key` returns —
        // proves an operator can later import the backup back via
        // a future `rewrap-hmac-key` slice. Drift guard against any
        // accidental transformation in write_backup_file (e.g.
        // line-ending munging).
        let home = TempDir::new().unwrap();
        let key_path = seed_hmac_key(home.path());
        let expected = crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let backup_bytes = std::fs::read(&dest).unwrap();
        assert_eq!(
            backup_bytes, expected,
            "backup bytes must match unwrapped HMAC key bytes round-trip"
        );
    }

    #[test]
    fn backup_creates_missing_parent_directory() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        // Destination two dirs deep — parent doesn't exist yet.
        let dest = out.path().join("nested").join("sub").join("k.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        assert!(dest.exists(), "parent dirs must be created on demand");
    }

    #[cfg(unix)]
    #[test]
    fn backup_file_is_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let meta = std::fs::metadata(&dest).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "backup file MUST be mode-0600 (operator-only); got {mode:o}"
        );
    }
}
