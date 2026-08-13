use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use neothd::config::FreedomConfig;
use neothd::media::{Asset, AssetKind, MediaExtractor, pdf::PdfExtractor};

const WORKER_MODE_ENV: &str = "NEOTH_INTERNAL_PDF_WORKER_V1";
const WORKER_JOB_ENV: &str = "NEOTH_INTERNAL_PDF_JOB";
#[cfg(target_os = "macos")]
const WORKER_PARENT_LIVENESS_FD_ENV: &str = "NEOTH_INTERNAL_PDF_PARENT_LIVENESS_FD";
const INPUT_MAGIC: &[u8; 8] = b"NTHPDI01";

fn neoth_bin() -> &'static str {
    env!("CARGO_BIN_EXE_neoth")
}

#[test]
fn internal_worker_rejects_an_uncontained_direct_invocation() {
    let mut command = Command::new(neoth_bin());
    command
        .env(WORKER_MODE_ENV, "parse")
        .env_remove(WORKER_JOB_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "macos")]
    command.env_remove(WORKER_PARENT_LIVENESS_FD_ENV);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        // A dedicated process group by itself must not satisfy the containment
        // contract: Linux additionally requires the authenticated parent-death
        // signal, macOS requires its live stdin lease, and unsupported Unix
        // platforms fail closed.
        command.process_group(0);
    }
    let mut child = command.spawn().expect("spawn private worker entrypoint");

    let mut request = Vec::with_capacity(INPUT_MAGIC.len() + 1 + 8);
    request.extend_from_slice(INPUT_MAGIC);
    request.push(1);
    request.extend_from_slice(&0_u64.to_be_bytes());
    child
        .stdin
        .take()
        .expect("worker stdin")
        .write_all(&request)
        .expect("write worker handshake");

    let started = Instant::now();
    let output = child.wait_with_output().expect("wait for private worker");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "uncontained worker must fail before parsing or waiting"
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    #[cfg(not(target_os = "macos"))]
    assert!(
        stderr.contains("parent-death signal")
            || stderr.contains("Job Object name is missing")
            || stderr.contains("parent-liveness containment is unavailable"),
        "unexpected private-worker error: {stderr}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        stderr.contains("parent-liveness lease"),
        "direct macOS worker must reject the missing authenticated parent-liveness lease: {stderr}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test]
async fn public_extractor_uses_the_verified_sibling_worker() {
    let asset = Asset::Bytes {
        kind: AssetKind::Pdf,
        mime: "application/pdf".into(),
        data: b"not actually a PDF".to_vec(),
    };
    let error = PdfExtractor
        .extract(&asset)
        .await
        .expect_err("invalid PDF must fail inside the isolated sibling worker");
    let message = error.to_string();
    assert!(
        message.contains("isolated PDF worker failed") && message.contains("parse PDF"),
        "extraction did not cross the verified isolated worker boundary: {message}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn cli_pdf_ingest_crosses_the_real_isolated_worker_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pdf = dir.path().join("invalid.pdf");
    std::fs::write(&pdf, b"%PDF-1.7\nnot a valid object graph").expect("write invalid PDF");
    let db = dir.path().join("views.db");
    let wal = dir.path().join("000001.wal");
    std::fs::write(
        dir.path().join("freedom.yaml"),
        serde_yaml::to_string(&FreedomConfig::default()).expect("serialize default config"),
    )
    .expect("write freedom.yaml");

    let output = Command::new(neoth_bin())
        .env("NEOTH_HOME", dir.path())
        .env("NEOTH_LOG", "error")
        .args(["--output", "json", "ingest"])
        .arg(&pdf)
        .arg("--db")
        .arg(&db)
        .arg("--wal-segment")
        .arg(&wal)
        .args(["--no-persist", "--no-audit"])
        .output()
        .expect("run real PDF ingest");

    assert!(!output.status.success(), "invalid PDF must fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("isolated PDF worker failed")
            || stderr.contains("parse PDF")
            || stderr.contains("PDF worker"),
        "ingest did not reach the isolated worker boundary: {stderr}"
    );
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
#[tokio::test]
async fn public_extractor_fails_closed_without_parent_liveness_containment() {
    let asset = Asset::Bytes {
        kind: AssetKind::Pdf,
        mime: "application/pdf".into(),
        data: b"not actually a PDF".to_vec(),
    };
    let error = PdfExtractor
        .extract(&asset)
        .await
        .expect_err("unsupported Unix parent-liveness boundary must fail closed");
    assert!(
        error
            .to_string()
            .contains("parent-liveness containment is unavailable"),
        "unexpected fail-closed error: {error}"
    );
}

#[test]
fn source_keeps_macos_parent_liveness_and_unsupported_bsd_fail_closed() {
    let source = include_str!("../src/media/pdf.rs");
    assert!(
        source.contains("arm_pdf_worker_parent_liveness_watchdog"),
        "macOS worker must arm its stdin parent-liveness watchdog"
    );
    assert!(
        source.contains("macos_pdf_worker_address_space_ceiling")
            && source.contains("libc::PROC_PIDTASKINFO")
            && source.contains("libc::RLIMIT_AS"),
        "macOS must use a measured total-address-space ceiling, not a fixed data-segment limit"
    );
    assert!(
        !source.contains("libc::RLIMIT_DATA,\n        PDF_WORKER_MEMORY_BYTES as u64"),
        "macOS must not reintroduce the fixed RLIMIT_DATA limit that XNU rejects after exec"
    );
    assert!(
        source.contains("Keep them explicitly fail-closed"),
        "unsupported BSD targets must retain an explicit fail-closed branch"
    );
    assert!(
        source.contains("PDF_WORKER_CLEANUP_TIMEOUT"),
        "worker cancellation must retain bounded direct-child reaping"
    );
}

#[test]
fn source_keeps_the_budget_permit_owned_until_verified_cleanup() {
    let source = include_str!("../src/media/pdf.rs");
    assert!(
        source.contains("struct PdfWorkerBudgetLease")
            && source.contains("budget: Option<PdfWorkerBudgetLease>")
            && !source.contains("let _permit ="),
        "the supervisor must own the singleton PDF budget lease"
    );
    assert!(
        source.contains("std::mem::forget(permit)")
            && source.contains("PDF_WORKER_BUDGET_POISONED"),
        "unverified or runtime-cancelled cleanup must poison admission fail-closed"
    );
    assert!(
        source.contains("release_after_verified_cleanup") && source.contains("cleanup_and_disarm"),
        "the permit may be released only by the verified cleanup path"
    );
    assert!(
        source.matches(".release_after_verified_cleanup()").count() >= 2
            && source.contains("drops this future during shutdown"),
        "normal and detached cleanup must retain the permit through proof or runtime cancellation"
    );
}

#[test]
fn source_keeps_unix_process_group_identity_pinned_until_tree_empty() {
    let source = include_str!("../src/media/pdf.rs");
    assert!(
        source.contains("libc::WNOWAIT") && source.contains("pdf_worker_terminal_without_reap"),
        "Unix cleanup must retain the unreaped leader as its PID/PGID identity pin"
    );
    assert!(
        source.contains("linux_pdf_process_group_is_empty_except_leader")
            && source.contains("macos_pdf_process_group_is_empty_except_leader")
            && source.contains("libc::proc_listpgrppids"),
        "Linux and macOS cleanup must prove that no process-tree members survive"
    );
    assert!(
        source.contains("refusing to signal a numeric PDF process group after leader reap"),
        "numeric PGID termination must fail closed after leader reap"
    );
    assert!(
        source.contains("QueryInformationJobObject") && source.contains("ActiveProcesses == 0"),
        "Windows cleanup must retain its Job handle until the process tree is empty"
    );
}
