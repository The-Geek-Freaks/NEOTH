//! GOLD-ADAPT-AWE-DOC-01 — Docling subprocess extractor.
//!
//! `DoclingExtractor` invokes the `docling` CLI (or `python -m docling`)
//! as a headless subprocess, captures its JSON output, and returns the
//! concatenated page text as an [`Extraction`].
//!
//! **Opt-in**: the extractor returns [`ExtractionError::Unsupported`] (not
//! [`ExtractionError::Backend`]) when:
//! - `MediaConfig::docling_enabled` is `false`, OR
//! - the `docling` binary is not on `PATH`.
//!
//! Both conditions cause `route_to_first_match` to fall through to the next
//! registered backend (`PdfExtractor` / `DocumentExtractor`), so the rest of
//! the ingest pipeline is **completely unaffected** when Docling is absent.
//!
//! **Supported asset kinds**: `Pdf`, `Document`, `Image`. All others
//! immediately return `Unsupported`.
//!
//! **Docling JSON contract** (pinned to Docling ≥ 2.x with `--output-format json`):
//! ```json
//! {
//!   "pages": [
//!     { "text": "page body …" },
//!     …
//!   ]
//! }
//! ```
//! If the JSON shape differs (older builds emit `content.text` or plain
//! markdown), the parser falls back to treating the raw stdout as text.

use std::{
    fmt,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Subprocess stdout cap — 50 MiB. Docling on a 1000-page PDF is the worst
/// case; anything larger implies a corrupted input.
const MAX_STDOUT_BYTES: usize = 50 * 1024 * 1024;

/// Subprocess wall-clock timeout. Docling needs to run an ML model on every
/// page; 5 minutes covers even a very large document on a slow CPU.
const SUBPROCESS_TIMEOUT_SECS: u64 = 300;

/// Subprocess stderr cap — 16 KiB of diagnostics is plenty for an error
/// message. We keep reading stderr past this cap (to EOF) so the OS pipe never
/// fills and deadlocks the child mid-write; only storage is bounded.
const MAX_STDERR_BYTES: usize = 16 * 1024;

const MAX_IMAGE_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DOCUMENT_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Parsed text is intentionally smaller than the subprocess wire cap. The
/// stdout buffer, JSON decoder scratch and final extraction can therefore
/// coexist without an attacker-controlled second 50 MiB copy. This matches the
/// canonical text ceiling used by the pure-Rust document and PDF extractors.
const MAX_EXTRACTED_TEXT_BYTES: usize = 8 * 1024 * 1024;
/// A page-count cap bounds per-page parser work even when every page contains
/// only an empty object.
const MAX_PAGE_COUNT: usize = 16_384;
const MAX_DOCLING_PATH_UNITS: usize = 32 * 1024;
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const PROCESS_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DOCLING_WORKER_CONCURRENCY: usize = 1;

static DOCLING_WORKER_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(DOCLING_WORKER_CONCURRENCY);

struct DoclingWorkPermit {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

async fn acquire_docling_work_permit() -> Result<DoclingWorkPermit, ExtractionError> {
    let permit = DOCLING_WORKER_BUDGET
        .acquire()
        .await
        .map_err(|_| ExtractionError::Backend {
            backend: "docling",
            reason: "global Docling worker budget is closed after an unverified cleanup".into(),
        })?;
    Ok(DoclingWorkPermit { _permit: permit })
}

pub struct DoclingExtractor {
    enabled: bool,
}

impl DoclingExtractor {
    /// Bind Docling to the caller's already-resolved effective media policy.
    /// Extractors must not reload a different default-instance config.
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

#[async_trait::async_trait]
impl MediaExtractor for DoclingExtractor {
    fn name(&self) -> &'static str {
        "docling"
    }

    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        // ── Gate 1: operator opt-in ──────────────────────────────────────────
        if !self.enabled {
            return Err(ExtractionError::Unsupported {
                backend: "docling",
                got: asset.kind(),
            });
        }

        // ── Gate 2: asset kind ───────────────────────────────────────────────
        match asset.kind() {
            AssetKind::Pdf | AssetKind::Document | AssetKind::Image => {}
            other => {
                return Err(ExtractionError::Unsupported {
                    backend: "docling",
                    got: other,
                });
            }
        }

        // Serialize the complete request-controlled lifetime before cloning the
        // borrowed asset into the detached owner. The permit, owned input,
        // private snapshot, process tree and pipe tasks remain under that one
        // supervisor until cleanup is proven.
        let permit = acquire_docling_work_permit().await?;
        let owned_asset = own_docling_input(asset)?;
        // A dropped JoinHandle detaches rather than aborts the task. Snapshot
        // creation therefore cannot fall back to an error-silencing TempDir
        // Drop merely because the caller was cancelled.
        let supervisor = tokio::spawn(run_owned_docling_supervisor(
            owned_asset,
            permit,
            DoclingRunLimits::production(),
        ));
        let mut caller_wait = DoclingCallerWaitGuard::armed();
        let joined = supervisor.await;
        caller_wait.mark_complete();
        let output = joined.map_err(|error| ExtractionError::Backend {
            backend: "docling",
            reason: format!("Docling supervisor task failed: {error}"),
        })??;

        // ── Parse JSON output ────────────────────────────────────────────────
        let (text, page_count) =
            parse_docling_output(&output.stdout).map_err(|reason| ExtractionError::Backend {
                backend: "docling",
                reason,
            })?;

        let metadata = serde_json::json!({
            "extractor": "docling",
            "page_count": page_count,
            "format": output.format,
        });

        Ok(Extraction { text, metadata })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct DoclingRunLimits {
    work_timeout: Duration,
    reap_timeout: Duration,
    pipe_timeout: Duration,
    max_stdout_bytes: usize,
}

impl DoclingRunLimits {
    const fn production() -> Self {
        Self {
            work_timeout: Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
            reap_timeout: CHILD_REAP_TIMEOUT,
            pipe_timeout: PIPE_DRAIN_TIMEOUT,
            max_stdout_bytes: MAX_STDOUT_BYTES,
        }
    }
}

struct DoclingSupervisorOutput {
    stdout: Vec<u8>,
    format: String,
}

struct DoclingCallerWaitGuard {
    completed: bool,
}

impl DoclingCallerWaitGuard {
    const fn armed() -> Self {
        Self { completed: false }
    }

    fn mark_complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for DoclingCallerWaitGuard {
    fn drop(&mut self) {
        if !self.completed {
            tracing::warn!(
                "Docling caller was cancelled; detached supervisor retains the permit, private \
                 snapshot and process tree until cleanup is proven"
            );
        }
    }
}

async fn run_owned_docling_supervisor(
    input: OwnedDoclingInput,
    permit: DoclingWorkPermit,
    limits: DoclingRunLimits,
) -> Result<DoclingSupervisorOutput, ExtractionError> {
    let asset_kind = input.kind();
    // Never hand an ambient operator path to the subprocess. Both path and
    // byte assets are copied into a private work tree under an internal
    // per-kind cap; path inputs are opened no-follow and read once.
    let (file_path, tempfile_guard) = prepare_docling_input(&input).await?;
    let format = file_path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    // The private snapshot is now authoritative. Release the caller-owned copy
    // before starting the ML process while retaining the global work permit.
    drop(input);

    let mut command = Command::new("docling");
    command
        .args(["--output-format", "json"])
        .arg(&file_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let stdout =
        run_docling_supervisor(command, tempfile_guard, permit, asset_kind, limits).await?;
    Ok(DoclingSupervisorOutput { stdout, format })
}

async fn run_docling_supervisor(
    mut command: Command,
    tempfile_guard: crate::util::private_temp::PrivateTempDir,
    _permit: DoclingWorkPermit,
    asset_kind: AssetKind,
    limits: DoclingRunLimits,
) -> Result<Vec<u8>, ExtractionError> {
    let containment_setup = match DoclingContainmentSetup::configure(&mut command) {
        Ok(setup) => setup,
        Err(error) => {
            return finish_docling_without_child(tempfile_guard, error, limits.reap_timeout).await;
        }
    };

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let extraction_error = if error.kind() == std::io::ErrorKind::NotFound {
                ExtractionError::Unsupported {
                    backend: "docling",
                    got: asset_kind,
                }
            } else {
                ExtractionError::Backend {
                    backend: "docling",
                    reason: format!("spawn failed: {error}"),
                }
            };
            return finish_docling_without_child(
                tempfile_guard,
                extraction_error,
                limits.reap_timeout,
            )
            .await;
        }
    };

    let mut containment = match containment_setup.activate(&child) {
        Ok(containment) => containment,
        Err(error) => {
            let process_cleanup = terminate_direct_child_bounded(&mut child, limits.reap_timeout)
                .await
                .err();
            let temp_cleanup = close_private_temp_dir_after_reap(
                tempfile_guard,
                process_cleanup.as_deref(),
                limits.reap_timeout,
            )
            .await
            .err();
            let mut reason = error.to_string();
            append_cleanup_error(&mut reason, process_cleanup.as_deref());
            append_cleanup_error(&mut reason, temp_cleanup.as_deref());
            if process_cleanup.is_some() || temp_cleanup.is_some() {
                poison_docling_worker_budget(&reason);
            }
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason,
            });
        }
    };
    if let Err(error) = containment.resume_child(&child) {
        return finish_docling_with_child(
            child,
            containment,
            None,
            tempfile_guard,
            error.to_string(),
            limits,
        )
        .await;
    }

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return finish_docling_with_child(
                child,
                containment,
                None,
                tempfile_guard,
                "Docling child did not expose its configured stdout pipe".into(),
                limits,
            )
            .await;
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return finish_docling_with_child(
                child,
                containment,
                None,
                tempfile_guard,
                "Docling child did not expose its configured stderr pipe".into(),
                limits,
            )
            .await;
        }
    };
    let stderr_task = tokio::spawn(drain_to_eof_capped(stderr, MAX_STDERR_BYTES));
    let work_deadline = tokio::time::Instant::now() + limits.work_timeout;

    let (stdout_bytes, mut failure) =
        match tokio::time::timeout_at(work_deadline, read_stdout_bounded(stdout, limits)).await {
            Ok(Ok(bytes)) => (Some(bytes), None),
            Ok(Err(error)) => (None, Some(error)),
            Err(_) => (
                None,
                Some(format!(
                    "subprocess timed out after {}s",
                    limits.work_timeout.as_secs_f64()
                )),
            ),
        };

    let mut status = None;
    if failure.is_none() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            match wait_for_docling_terminal_without_reap(containment.leader_pid(), work_deadline)
                .await
            {
                Ok(()) => {}
                Err(error) => failure = Some(error),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            match tokio::time::timeout_at(work_deadline, child.wait()).await {
                Ok(Ok(exit)) => status = Some(exit),
                Ok(Err(error)) => failure = Some(format!("wait failed: {error}")),
                Err(_) => failure = Some("subprocess did not exit after stdout close".into()),
            }
        }
    }

    let process_cleanup = terminate_docling_tree_bounded(
        &mut child,
        &mut containment,
        &mut status,
        limits.reap_timeout,
    )
    .await
    .err();
    drop(containment);
    let stderr_result = collect_stderr_task_with_timeout(stderr_task, limits.pipe_timeout).await;
    let temp_cleanup = close_private_temp_dir_after_reap(
        tempfile_guard,
        process_cleanup.as_deref(),
        limits.reap_timeout,
    )
    .await
    .err();

    let cleanup_failed =
        process_cleanup.is_some() || stderr_result.is_err() || temp_cleanup.is_some();
    if cleanup_failed {
        let mut cleanup_reason = String::new();
        append_cleanup_error(&mut cleanup_reason, process_cleanup.as_deref());
        append_cleanup_error(
            &mut cleanup_reason,
            stderr_result.as_ref().err().map(String::as_str),
        );
        append_cleanup_error(&mut cleanup_reason, temp_cleanup.as_deref());
        poison_docling_worker_budget(&cleanup_reason);
        if let Some(existing) = failure.as_mut() {
            append_cleanup_error(existing, Some(&cleanup_reason));
        } else {
            failure = Some(cleanup_reason);
        }
    }

    let stderr_bytes = stderr_result.unwrap_or_default();
    if let Some(mut reason) = failure {
        let diagnostic = sanitized_diagnostic(&stderr_bytes);
        if !diagnostic.is_empty() {
            reason.push_str("; stderr: ");
            reason.push_str(&diagnostic);
        }
        return Err(ExtractionError::Backend {
            backend: "docling",
            reason,
        });
    }

    let status = status.ok_or_else(|| ExtractionError::Backend {
        backend: "docling",
        reason: "subprocess exited without a status".into(),
    })?;
    if !status.success() {
        let code = status.code().unwrap_or(-1);
        let diagnostic = sanitized_diagnostic(&stderr_bytes);
        let reason = if diagnostic.is_empty() {
            format!("exit code {code}")
        } else {
            format!("exit code {code}: {diagnostic}")
        };
        return Err(ExtractionError::Backend {
            backend: "docling",
            reason,
        });
    }

    stdout_bytes.ok_or_else(|| ExtractionError::Backend {
        backend: "docling",
        reason: "subprocess produced no captured stdout state".into(),
    })
}

async fn finish_docling_without_child(
    tempfile_guard: crate::util::private_temp::PrivateTempDir,
    error: ExtractionError,
    cleanup_timeout: Duration,
) -> Result<Vec<u8>, ExtractionError> {
    match close_private_temp_dir_after_reap(tempfile_guard, None, cleanup_timeout).await {
        Ok(()) => Err(error),
        Err(cleanup_error) => {
            let reason = format!("{error}; cleanup: {cleanup_error}");
            poison_docling_worker_budget(&reason);
            Err(ExtractionError::Backend {
                backend: "docling",
                reason,
            })
        }
    }
}

async fn finish_docling_with_child(
    mut child: tokio::process::Child,
    mut containment: DoclingContainment,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    tempfile_guard: crate::util::private_temp::PrivateTempDir,
    mut reason: String,
    limits: DoclingRunLimits,
) -> Result<Vec<u8>, ExtractionError> {
    let mut status = None;
    let process_cleanup = terminate_docling_tree_bounded(
        &mut child,
        &mut containment,
        &mut status,
        limits.reap_timeout,
    )
    .await
    .err();
    drop(containment);
    let stderr_cleanup = match stderr_task {
        Some(task) => collect_stderr_task_with_timeout(task, limits.pipe_timeout)
            .await
            .err(),
        None => None,
    };
    let temp_cleanup = close_private_temp_dir_after_reap(
        tempfile_guard,
        process_cleanup.as_deref(),
        limits.reap_timeout,
    )
    .await
    .err();
    append_cleanup_error(&mut reason, process_cleanup.as_deref());
    append_cleanup_error(&mut reason, stderr_cleanup.as_deref());
    append_cleanup_error(&mut reason, temp_cleanup.as_deref());
    if process_cleanup.is_some() || stderr_cleanup.is_some() || temp_cleanup.is_some() {
        poison_docling_worker_budget(&reason);
    }
    Err(ExtractionError::Backend {
        backend: "docling",
        reason,
    })
}

async fn read_stdout_bounded(
    mut stdout: tokio::process::ChildStdout,
    limits: DoclingRunLimits,
) -> Result<Vec<u8>, String> {
    let initial_capacity = limits.max_stdout_bytes.min(64 * 1024);
    let mut output = Vec::new();
    output
        .try_reserve(initial_capacity)
        .map_err(|error| format!("reserve Docling stdout buffer: {error}"))?;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = stdout
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read Docling stdout: {error}"))?;
        if read == 0 {
            return Ok(output);
        }
        if read > limits.max_stdout_bytes.saturating_sub(output.len()) {
            return Err(format!("output exceeds {} bytes", limits.max_stdout_bytes));
        }
        output
            .try_reserve(read)
            .map_err(|error| format!("grow Docling stdout buffer: {error}"))?;
        output.extend_from_slice(&chunk[..read]);
    }
}

async fn terminate_docling_tree_bounded(
    child: &mut tokio::process::Child,
    containment: &mut DoclingContainment,
    exit_status: &mut Option<std::process::ExitStatus>,
    timeout: Duration,
) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        containment.terminate_tree(exit_status.is_some())?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let leader_terminal = docling_terminal_without_reap(containment.leader_pid())?;
            let tree_empty =
                leader_terminal && containment.process_tree_is_empty_except_leader()?;
            if leader_terminal && tree_empty {
                // Disarm the numeric-PGID Drop backstop before reap. From this
                // point the group is proven to contain only the pinned zombie,
                // so no further group signal is useful or identity-safe.
                containment.disarm();
                match child.try_wait() {
                    Ok(Some(status)) => {
                        *exit_status = Some(status);
                        return Ok(());
                    }
                    Ok(None) => {
                        return Err(
                            "Docling terminal state vanished before identity-safe reap".into()
                        );
                    }
                    Err(error) => return Err(format!("reap Docling child: {error}")),
                }
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "Docling cleanup exceeded {}s before tree-empty proof and direct-child reap",
                    timeout.as_secs_f64()
                ));
            }
            tokio::time::sleep_until((now + PROCESS_CLEANUP_POLL_INTERVAL).min(deadline)).await;
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let mut errors = Vec::new();
        if let Err(error) = containment.terminate_tree(exit_status.is_some()) {
            errors.push(error);
        }
        if let Err(error) = terminate_direct_child_bounded(child, timeout).await {
            errors.push(error);
        } else if exit_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => *exit_status = Some(status),
                Ok(None) => errors.push("Docling child was not reaped after bounded wait".into()),
                Err(error) => errors.push(format!("inspect reaped Docling child: {error}")),
            }
        }
        match containment.wait_empty(timeout).await {
            Ok(()) => containment.disarm(),
            Err(error) => errors.push(error),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

async fn terminate_direct_child_bounded(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> Result<(), String> {
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(error = %error, "inspect Docling child before termination failed");
        }
    }

    if let Err(kill_error) = child.start_kill() {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            _ => return Err(format!("start_kill Docling child: {kill_error}")),
        }
    }

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!("reap Docling child: {error}")),
        Err(_) => Err(format!(
            "reap Docling child exceeded {}s",
            timeout.as_secs_f64()
        )),
    }
}

async fn collect_stderr_task_with_timeout(
    mut task: tokio::task::JoinHandle<Vec<u8>>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(format!("join Docling stderr drain: {error}")),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(format!(
                "Docling stderr drain exceeded {}s",
                timeout.as_secs_f64()
            ))
        }
    }
}

async fn close_private_temp_dir_after_reap(
    tempfile_guard: crate::util::private_temp::PrivateTempDir,
    process_cleanup_error: Option<&str>,
    timeout: Duration,
) -> Result<(), String> {
    if let Some(process_cleanup_error) = process_cleanup_error {
        let retained_path = tempfile_guard.path().to_path_buf();
        // The process tree may still be reading this directory. Keep the
        // protected work tree in place instead of racing a live descendant;
        // the global budget is poisoned by the caller so no further Docling
        // work starts until the daemon is restarted and the operator can
        // inspect/remove this exceptional residue.
        std::mem::forget(tempfile_guard);
        return Err(format!(
            "private Docling work tree {} retained because process cleanup was unverified: \
             {process_cleanup_error}",
            retained_path.display()
        ));
    }
    let mut cleanup = tokio::task::spawn_blocking(move || tempfile_guard.close());
    match tokio::time::timeout(timeout, &mut cleanup).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(format!("remove private Docling work tree: {error}")),
        Ok(Err(error)) => Err(format!("join private Docling cleanup: {error}")),
        Err(_) => {
            cleanup.abort();
            Err(format!(
                "private Docling cleanup exceeded {}s",
                timeout.as_secs_f64()
            ))
        }
    }
}

fn append_cleanup_error(reason: &mut String, cleanup_error: Option<&str>) {
    let Some(cleanup_error) = cleanup_error.filter(|error| !error.is_empty()) else {
        return;
    };
    if !reason.is_empty() {
        reason.push_str("; cleanup: ");
    }
    reason.push_str(cleanup_error);
}

fn poison_docling_worker_budget(reason: &str) {
    DOCLING_WORKER_BUDGET.close();
    tracing::error!(
        reason,
        "Docling cleanup could not be proven; future Docling work blocked fail-closed"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_for_docling_terminal_without_reap(
    child_pid: libc::pid_t,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    loop {
        if docling_terminal_without_reap(child_pid)? {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err("subprocess did not exit after stdout close".into());
        }
        tokio::time::sleep_until((now + PROCESS_CLEANUP_POLL_INTERVAL).min(deadline)).await;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn docling_terminal_without_reap(child_pid: libc::pid_t) -> Result<bool, String> {
    let wait_id = libc::id_t::try_from(child_pid)
        .map_err(|_| "Docling PID does not fit waitid identity".to_string())?;
    // SAFETY: zero is the required initial state for a WNOHANG siginfo_t and
    // waitid writes only to this live object. WNOWAIT deliberately retains the
    // zombie/PID, pinning the numeric process-group identity until every
    // descendant has been killed and group membership has been proven empty.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `wait_id` identifies our direct child and `info` is valid writable
    // storage for the duration of this synchronous syscall.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            wait_id,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(format!(
            "observe Docling terminal state without reaping: {error}"
        ));
    }
    // SAFETY: waitid initialized the SIGCHLD view. With WNOHANG, si_pid is
    // zero until a matching child reaches a terminal state.
    Ok(unsafe { info.si_pid() } == child_pid)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct DoclingContainmentSetup;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl DoclingContainmentSetup {
    fn configure(command: &mut Command) -> Result<Self, ExtractionError> {
        // The child becomes the leader of a fresh process group. Every
        // descendant inherits that group unless it explicitly escapes it;
        // cleanup targets the negative PGID rather than only the Python parent.
        command.process_group(0);
        Ok(Self)
    }

    fn activate(
        self,
        child: &tokio::process::Child,
    ) -> Result<DoclingContainment, ExtractionError> {
        let pid = child.id().ok_or_else(|| ExtractionError::Backend {
            backend: "docling",
            reason: "Docling child exited before process-group activation".into(),
        })?;
        let pgid = libc::pid_t::try_from(pid).map_err(|_| ExtractionError::Backend {
            backend: "docling",
            reason: "Docling PID does not fit a POSIX process-group id".into(),
        })?;
        Ok(DoclingContainment { pgid, armed: true })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct DoclingContainment {
    pgid: libc::pid_t,
    armed: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl DoclingContainment {
    fn resume_child(&self, _child: &tokio::process::Child) -> Result<(), ExtractionError> {
        Ok(())
    }

    fn leader_pid(&self) -> libc::pid_t {
        self.pgid
    }

    fn terminate_tree(&self, leader_reaped: bool) -> Result<(), String> {
        if leader_reaped {
            return Err("refusing to signal a numeric Docling PGID after leader reap".into());
        }
        // SAFETY: `pgid` is the positive PID returned after spawning with
        // process_group(0). The unreaped leader still owns that PID, so
        // negating it cannot target a subsequently reused group identity.
        if unsafe { libc::kill(-self.pgid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("kill Docling process group: {error}"))
        }
    }

    fn process_tree_is_empty_except_leader(&self) -> Result<bool, String> {
        #[cfg(target_os = "linux")]
        {
            linux_docling_process_group_is_empty_except_leader(self.pgid)
        }
        #[cfg(target_os = "macos")]
        {
            macos_docling_process_group_is_empty_except_leader(self.pgid)
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for DoclingContainment {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Synchronous panic/runtime-shutdown backstop. This guard is disarmed
        // before the direct child is reaped, so it can never signal a recycled
        // numeric process-group identity.
        // SAFETY: while armed, the unreaped child leader pins this positive
        // PGID; negating it therefore still identifies only that child group.
        unsafe {
            libc::kill(-self.pgid, libc::SIGKILL);
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_docling_process_group_is_empty_except_leader(
    leader_pid: libc::pid_t,
) -> Result<bool, String> {
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| format!("enumerate /proc for Docling cleanup: {error}"))?;
    let mut saw_leader = false;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("enumerate Docling process-group member: {error}"))?;
        let file_name = entry.file_name();
        let Some(pid_text) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<libc::pid_t>() else {
            continue;
        };
        // SAFETY: getpgid reads kernel process metadata for this numeric /proc
        // entry and writes through no pointers.
        let process_group = unsafe { libc::getpgid(pid) };
        if process_group < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(format!(
                "inspect /proc/{pid} process group for Docling cleanup: {error}"
            ));
        }
        if process_group != leader_pid {
            continue;
        }
        if pid != leader_pid {
            return Ok(false);
        }
        saw_leader = true;
    }
    if !saw_leader {
        return Err("unreaped Docling leader was absent from /proc group-empty proof".into());
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn macos_docling_process_group_is_empty_except_leader(
    leader_pid: libc::pid_t,
) -> Result<bool, String> {
    const PID_CAPACITY: usize = 64;
    let mut pids = [0; PID_CAPACITY];
    let buffer_bytes = libc::c_int::try_from(std::mem::size_of_val(&pids))
        .map_err(|_| "macOS Docling process-group buffer does not fit c_int".to_string())?;
    // SAFETY: `pids` is writable storage for `buffer_bytes`. The unreaped
    // waitid identity pins the group number for the full query.
    let count = unsafe {
        libc::proc_listpgrppids(
            leader_pid,
            pids.as_mut_ptr().cast::<libc::c_void>(),
            buffer_bytes,
        )
    };
    if count < 0 {
        return Err(format!(
            "enumerate macOS Docling process-group members: {}",
            std::io::Error::last_os_error()
        ));
    }
    let count = usize::try_from(count)
        .map_err(|_| "macOS Docling process-group member count is invalid".to_string())?;
    if count >= pids.len() {
        return Ok(false);
    }
    let members = &pids[..count];
    if !members.contains(&leader_pid) {
        return Err("unreaped Docling leader was absent from macOS group-empty proof".into());
    }
    Ok(members.iter().all(|pid| *pid <= 0 || *pid == leader_pid))
}

#[cfg(windows)]
struct DoclingContainmentSetup {
    job: WindowsDoclingJob,
}

#[cfg(windows)]
impl DoclingContainmentSetup {
    fn configure(command: &mut Command) -> Result<Self, ExtractionError> {
        use std::os::windows::process::CommandExt as _;

        // The untrusted snapshot path must not execute before the child belongs
        // to our KILL_ON_JOB_CLOSE boundary. Tokio does not expose the primary
        // thread handle, so create the whole process suspended and resume it by
        // process handle only after AssignProcessToJobObject succeeds.
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command
            .as_std_mut()
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        WindowsDoclingJob::create().map(|job| Self { job })
    }

    fn activate(
        self,
        child: &tokio::process::Child,
    ) -> Result<DoclingContainment, ExtractionError> {
        self.job.assign(child)?;
        Ok(DoclingContainment { job: self.job })
    }
}

#[cfg(windows)]
struct DoclingContainment {
    job: WindowsDoclingJob,
}

#[cfg(windows)]
impl DoclingContainment {
    fn resume_child(&self, child: &tokio::process::Child) -> Result<(), ExtractionError> {
        self.job.resume(child)
    }

    fn terminate_tree(&self, _leader_reaped: bool) -> Result<(), String> {
        self.job.terminate()
    }

    async fn wait_empty(&self, timeout: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.job.active_processes() {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) => return Err(error),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Docling Job Object remained non-empty after {}s",
                    timeout.as_secs_f64()
                ));
            }
            tokio::time::sleep(PROCESS_CLEANUP_POLL_INTERVAL).await;
        }
    }

    fn disarm(&mut self) {}
}

#[cfg(windows)]
struct WindowsDoclingJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtResumeProcess"]
    fn nt_resume_process(process_handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
}

#[cfg(windows)]
impl WindowsDoclingJob {
    fn create() -> Result<Self, ExtractionError> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: null security attributes and name request a fresh unnamed Job
        // Object owned only by this process.
        let raw_handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_handle.is_null() {
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason: format!(
                    "create Docling Job Object: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        // SAFETY: CreateJobObjectW returned a fresh non-null handle. Ownership
        // moves exactly once into OwnedHandle, which closes it on every return.
        let handle =
            unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_handle.cast()) };

        // SAFETY: all-zero is a valid base for this Win32 POD structure.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 64;
        // SAFETY: `handle` is live and `info` remains valid for the complete
        // synchronous call.
        if unsafe {
            SetInformationJobObject(
                Self::raw_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason: format!("configure Docling Job Object: {error}"),
            });
        }
        Ok(Self { handle })
    }

    fn raw_handle(
        handle: &std::os::windows::io::OwnedHandle,
    ) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle as _;

        handle.as_raw_handle().cast()
    }

    fn assign(&self, child: &tokio::process::Child) -> Result<(), ExtractionError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let child_handle = child.raw_handle().ok_or_else(|| ExtractionError::Backend {
            backend: "docling",
            reason: "Docling child exited before Job Object assignment".into(),
        })?;
        // SAFETY: both kernel handles are live for this synchronous call.
        if unsafe { AssignProcessToJobObject(Self::raw_handle(&self.handle), child_handle.cast()) }
            == 0
        {
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason: format!(
                    "assign Docling child to Job Object: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        Ok(())
    }

    fn resume(&self, child: &tokio::process::Child) -> Result<(), ExtractionError> {
        let child_handle = child.raw_handle().ok_or_else(|| ExtractionError::Backend {
            backend: "docling",
            reason: "Docling child exited before its suspended process could be resumed".into(),
        })?;
        // SAFETY: `child_handle` is the live process handle returned by the
        // successful CREATE_SUSPENDED spawn. The process is already assigned to
        // `self.handle`, which remains owned for the complete call.
        let status = unsafe { nt_resume_process(child_handle.cast()) };
        if status != 0 {
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason: format!(
                    "resume suspended Docling child failed with NTSTATUS {:#010x}",
                    status as u32
                ),
            });
        }
        Ok(())
    }

    fn terminate(&self) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the guard retains ownership of this live Job Object handle.
        if unsafe { TerminateJobObject(Self::raw_handle(&self.handle), 1) } == 0 {
            Err(format!(
                "terminate Docling Job Object: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn active_processes(&self) -> Result<u32, String> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        // SAFETY: all-zero is a valid base and the API writes the complete POD.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the Job Object and output buffer remain live for this call.
        if unsafe {
            QueryInformationJobObject(
                Self::raw_handle(&self.handle),
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(format!(
                "query Docling Job Object: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(info.ActiveProcesses)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
struct DoclingContainmentSetup;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl DoclingContainmentSetup {
    fn configure(_command: &mut Command) -> Result<Self, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "docling",
            reason: "Docling process-tree containment is unavailable on this platform".into(),
        })
    }

    fn activate(
        self,
        _child: &tokio::process::Child,
    ) -> Result<DoclingContainment, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "docling",
            reason: "Docling process-tree containment is unavailable on this platform".into(),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
struct DoclingContainment;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl DoclingContainment {
    fn resume_child(&self, _child: &tokio::process::Child) -> Result<(), ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "docling",
            reason: "Docling process-tree containment is unavailable on this platform".into(),
        })
    }

    fn terminate_tree(&self, _leader_reaped: bool) -> Result<(), String> {
        Err("Docling process-tree containment is unavailable on this platform".into())
    }

    async fn wait_empty(&self, _timeout: Duration) -> Result<(), String> {
        Err("Docling process-tree containment is unavailable on this platform".into())
    }

    fn disarm(&mut self) {}
}

enum OwnedDoclingInput {
    Bytes {
        kind: AssetKind,
        extension: String,
        data: Vec<u8>,
    },
    Path {
        kind: AssetKind,
        extension: String,
        path: PathBuf,
    },
}

impl OwnedDoclingInput {
    fn kind(&self) -> AssetKind {
        match self {
            Self::Bytes { kind, .. } | Self::Path { kind, .. } => *kind,
        }
    }

    fn extension(&self) -> &str {
        match self {
            Self::Bytes { extension, .. } | Self::Path { extension, .. } => extension,
        }
    }
}

fn own_docling_input(asset: &Asset) -> Result<OwnedDoclingInput, ExtractionError> {
    let limit = docling_input_limit(asset.kind());
    let extension = safe_docling_extension(asset);
    match asset {
        Asset::Bytes { kind, data, .. } => {
            ensure_docling_input_size(data.len() as u64, limit)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(data.len())
                .map_err(|error| ExtractionError::Backend {
                    backend: "docling",
                    reason: format!("reserve owned Docling input: {error}"),
                })?;
            owned.extend_from_slice(data);
            Ok(OwnedDoclingInput::Bytes {
                kind: *kind,
                extension,
                data: owned,
            })
        }
        Asset::Path { kind, path, .. } => {
            let path_units = docling_path_units(path);
            if path_units > MAX_DOCLING_PATH_UNITS {
                return Err(ExtractionError::Backend {
                    backend: "docling",
                    reason: format!(
                        "input path exceeds the {MAX_DOCLING_PATH_UNITS}-unit transport limit"
                    ),
                });
            }
            Ok(OwnedDoclingInput::Path {
                kind: *kind,
                extension,
                path: path.clone(),
            })
        }
    }
}

#[cfg(unix)]
fn docling_path_units(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt as _;

    path.as_os_str().as_bytes().len()
}

#[cfg(windows)]
fn docling_path_units(path: &Path) -> usize {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str().encode_wide().count()
}

#[cfg(not(any(unix, windows)))]
fn docling_path_units(path: &Path) -> usize {
    path.as_os_str().len()
}

async fn prepare_docling_input(
    input: &OwnedDoclingInput,
) -> Result<(PathBuf, crate::util::private_temp::PrivateTempDir), ExtractionError> {
    let limit = docling_input_limit(input.kind());
    let extension = input.extension().to_owned();
    match input {
        OwnedDoclingInput::Bytes { data, .. } => {
            ensure_docling_input_size(data.len() as u64, limit)?;
            let dir = crate::util::private_temp::directory(".neoth-docling-")
                .map_err(|e| ExtractionError::Io(e.to_string()))?;
            let target = dir.path().join(format!("docling_input{extension}"));
            if let Err(error) = tokio::fs::write(&target, data).await {
                let extraction_error = ExtractionError::Io(error.to_string());
                return match close_private_temp_dir_after_reap(dir, None, CHILD_REAP_TIMEOUT).await
                {
                    Ok(()) => Err(extraction_error),
                    Err(cleanup_error) => {
                        let reason = format!("{extraction_error}; cleanup: {cleanup_error}");
                        poison_docling_worker_budget(&reason);
                        Err(ExtractionError::Backend {
                            backend: "docling",
                            reason,
                        })
                    }
                };
            }
            Ok((target, dir))
        }
        OwnedDoclingInput::Path { path, .. } => {
            let source = path.clone();
            tokio::task::spawn_blocking(move || {
                let dir = crate::util::private_temp::directory(".neoth-docling-")
                    .map_err(|e| ExtractionError::Io(e.to_string()))?;
                let target = dir.path().join(format!("docling_input{extension}"));
                if let Err(extraction_error) = copy_docling_input_snapshot(&source, &target, limit)
                {
                    return match dir.close() {
                        Ok(()) => Err(extraction_error),
                        Err(cleanup_error) => {
                            let reason = format!("{extraction_error}; cleanup: {cleanup_error}");
                            poison_docling_worker_budget(&reason);
                            Err(ExtractionError::Backend {
                                backend: "docling",
                                reason,
                            })
                        }
                    };
                }
                Ok((target, dir))
            })
            .await
            .map_err(|e| ExtractionError::Backend {
                backend: "docling",
                reason: format!("input snapshot task failed: {e}"),
            })?
        }
    }
}

fn docling_input_limit(kind: AssetKind) -> u64 {
    match kind {
        AssetKind::Image => MAX_IMAGE_INPUT_BYTES,
        AssetKind::Pdf | AssetKind::Document => MAX_DOCUMENT_INPUT_BYTES,
        AssetKind::Audio | AssetKind::Video | AssetKind::Other => 0,
    }
}

fn ensure_docling_input_size(size: u64, limit: u64) -> Result<(), ExtractionError> {
    if size > limit {
        return Err(ExtractionError::Backend {
            backend: "docling",
            reason: format!("input exceeds {limit} bytes"),
        });
    }
    Ok(())
}

fn safe_docling_extension(asset: &Asset) -> String {
    if let Asset::Path { path, .. } = asset
        && let Some(extension) = path.extension().and_then(|value| value.to_str())
        && !extension.is_empty()
        && extension.len() <= 12
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return format!(".{}", extension.to_ascii_lowercase());
    }
    ext_from_mime(asset.mime()).to_owned()
}

fn open_docling_input_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn copy_docling_input_snapshot(
    source: &Path,
    target: &Path,
    limit: u64,
) -> Result<(), ExtractionError> {
    let mut input =
        open_docling_input_no_follow(source).map_err(|e| ExtractionError::Io(e.to_string()))?;
    let metadata = input
        .metadata()
        .map_err(|e| ExtractionError::Io(e.to_string()))?;
    if !metadata.is_file() || metadata_is_link_like(&metadata) {
        return Err(ExtractionError::Backend {
            backend: "docling",
            reason: "input is not a regular non-link file".into(),
        });
    }
    ensure_docling_input_size(metadata.len(), limit)?;
    let before_modified = metadata.modified().ok();

    let mut output =
        std::fs::File::create(target).map_err(|e| ExtractionError::Io(e.to_string()))?;
    let copied = std::io::copy(
        &mut std::io::Read::by_ref(&mut input).take(limit + 1),
        &mut output,
    )
    .map_err(|e| ExtractionError::Io(e.to_string()))?;
    ensure_docling_input_size(copied, limit)?;
    let after = input
        .metadata()
        .map_err(|e| ExtractionError::Io(e.to_string()))?;
    if metadata.len() != after.len()
        || before_modified != after.modified().ok()
        || copied != metadata.len()
    {
        return Err(ExtractionError::Backend {
            backend: "docling",
            reason: "input changed while it was being snapshotted".into(),
        });
    }
    output
        .flush()
        .map_err(|e| ExtractionError::Io(e.to_string()))?;
    Ok(())
}

fn sanitized_diagnostic(stderr: &[u8]) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 512;

    let lossy = String::from_utf8_lossy(stderr);
    let sanitized = crate::security::redact::sanitize_tool_output(lossy.trim());
    sanitized
        .split_whitespace()
        .flat_map(|part| part.chars().chain(std::iter::once(' ')))
        .take(MAX_DIAGNOSTIC_CHARS)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Drain an async reader to EOF, retaining at most `cap` bytes. Reading
/// continues past the cap so the underlying OS pipe never fills (which would
/// deadlock the child writing to it); the overflow is simply discarded. Used
/// for the child's stderr, which we keep only for diagnostics on failure.
async fn drain_to_eof_capped<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let room = cap - out.len();
                    out.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            Err(_) => break,
        }
    }
    out
}

/// Parse Docling's JSON output.
///
/// Docling ≥ 2.x `--output-format json` emits:
/// ```json
/// { "pages": [{ "text": "..." }, ...] }
/// ```
/// Older builds may emit `{ "content": { "text": "..." } }` or plain text.
/// Unknown JSON fields are consumed without constructing a `Value` tree.
/// Recognized text and page counts are hard-capped; exceeding either limit is a
/// visible error, never a partial/truncated extraction. A shape mismatch keeps
/// the legacy raw-text fallback, but that copy is subject to the same byte cap.
fn parse_docling_output(stdout: &[u8]) -> Result<(String, usize), String> {
    parse_docling_output_with_limits(stdout, DoclingParseLimits::production())
}

#[derive(Clone, Copy)]
struct DoclingParseLimits {
    max_page_count: usize,
    max_text_bytes: usize,
}

impl DoclingParseLimits {
    const fn production() -> Self {
        Self {
            max_page_count: MAX_PAGE_COUNT,
            max_text_bytes: MAX_EXTRACTED_TEXT_BYTES,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DoclingTextTarget {
    Pages,
    Content,
    TopLevel,
}

struct DoclingOutputAccumulator {
    limits: DoclingParseLimits,
    recognized_bytes: usize,
    pages_seen: usize,
    page_text_count: usize,
    pages_text: String,
    content_text: String,
    top_level_text: String,
    limit_error: Option<String>,
}

impl DoclingOutputAccumulator {
    fn new(limits: DoclingParseLimits) -> Self {
        Self {
            limits,
            recognized_bytes: 0,
            pages_seen: 0,
            page_text_count: 0,
            pages_text: String::new(),
            content_text: String::new(),
            top_level_text: String::new(),
            limit_error: None,
        }
    }

    fn error<E>(&mut self, message: String) -> E
    where
        E: de::Error,
    {
        if self.limit_error.is_none() {
            self.limit_error = Some(message);
        }
        E::custom(
            self.limit_error
                .as_deref()
                .unwrap_or("Docling parser limit was exceeded"),
        )
    }

    fn observe_page<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        if self.pages_seen >= self.limits.max_page_count {
            return Err(self.error(format!(
                "Docling JSON exceeds the {}-page parser limit",
                self.limits.max_page_count
            )));
        }
        self.pages_seen += 1;
        Ok(())
    }

    fn target_mut(&mut self, target: DoclingTextTarget) -> &mut String {
        match target {
            DoclingTextTarget::Pages => &mut self.pages_text,
            DoclingTextTarget::Content => &mut self.content_text,
            DoclingTextTarget::TopLevel => &mut self.top_level_text,
        }
    }

    fn checked_total<E>(&mut self, additional: usize) -> Result<usize, E>
    where
        E: de::Error,
    {
        let total = self
            .recognized_bytes
            .checked_add(additional)
            .ok_or_else(|| {
                self.error::<E>("Docling recognized-text byte count overflowed".into())
            })?;
        if total > self.limits.max_text_bytes {
            return Err(self.error(format!(
                "Docling text exceeds the {}-byte parser limit",
                self.limits.max_text_bytes
            )));
        }
        Ok(total)
    }

    fn append_borrowed<E>(&mut self, target: DoclingTextTarget, text: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        if text.trim().is_empty() {
            return Ok(());
        }
        let separator_bytes: usize =
            if target == DoclingTextTarget::Pages && !self.pages_text.is_empty() {
                2
            } else {
                0
            };
        let additional = separator_bytes.checked_add(text.len()).ok_or_else(|| {
            self.error::<E>("Docling recognized-text byte count overflowed".into())
        })?;
        let total = self.checked_total::<E>(additional)?;
        if let Err(error) = self.target_mut(target).try_reserve(additional) {
            return Err(self.error(format!("reserve bounded Docling extraction text: {error}")));
        }
        let output = self.target_mut(target);
        if separator_bytes != 0 {
            output.push_str("\n\n");
        }
        output.push_str(text);
        self.recognized_bytes = total;
        if target == DoclingTextTarget::Pages {
            self.page_text_count += 1;
        }
        Ok(())
    }

    fn append_owned<E>(&mut self, target: DoclingTextTarget, text: String) -> Result<(), E>
    where
        E: de::Error,
    {
        // Copy only the accepted bytes into our bounded output. Moving an
        // externally supplied String could retain an arbitrarily oversized
        // spare capacity even when its visible text is tiny.
        self.append_borrowed(target, &text)
    }

    fn into_extraction(self) -> Option<(String, usize)> {
        if !self.pages_text.is_empty() {
            return Some((self.pages_text, self.page_text_count));
        }
        if !self.content_text.is_empty() {
            return Some((self.content_text, 1));
        }
        if !self.top_level_text.is_empty() {
            return Some((self.top_level_text, 1));
        }
        None
    }
}

#[derive(Clone, Copy)]
enum DoclingField {
    Pages,
    Content,
    Text,
    Other,
}

struct DoclingFieldSeed;

impl<'de> DeserializeSeed<'de> for DoclingFieldSeed {
    type Value = DoclingField;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(DoclingFieldVisitor)
    }
}

struct DoclingFieldVisitor;

impl<'de> Visitor<'de> for DoclingFieldVisitor {
    type Value = DoclingField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Docling JSON object field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match value {
            "pages" => DoclingField::Pages,
            "content" => DoclingField::Content,
            "text" => DoclingField::Text,
            _ => DoclingField::Other,
        })
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

struct DoclingOutputSeed<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> DeserializeSeed<'de> for DoclingOutputSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(DoclingOutputVisitor {
            output: self.output,
        })
    }
}

struct DoclingOutputVisitor<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> Visitor<'de> for DoclingOutputVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Docling JSON output object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut pages_seen = false;
        let mut content_seen = false;
        let mut top_text_seen = false;
        while let Some(field) = map.next_key_seed(DoclingFieldSeed)? {
            match field {
                DoclingField::Pages if !pages_seen => {
                    pages_seen = true;
                    map.next_value_seed(DoclingPagesSeed {
                        output: &mut *self.output,
                    })?;
                }
                DoclingField::Content if !content_seen => {
                    content_seen = true;
                    map.next_value_seed(DoclingContentSeed {
                        output: &mut *self.output,
                    })?;
                }
                DoclingField::Text if !top_text_seen => {
                    top_text_seen = true;
                    map.next_value_seed(DoclingTextSeed {
                        output: &mut *self.output,
                        target: DoclingTextTarget::TopLevel,
                    })?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct DoclingPagesSeed<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> DeserializeSeed<'de> for DoclingPagesSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(DoclingPagesVisitor {
            output: self.output,
        })
    }
}

struct DoclingPagesVisitor<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> Visitor<'de> for DoclingPagesVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Docling pages array")
    }

    fn visit_seq<A>(self, mut pages: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while pages
            .next_element_seed(DoclingPageSeed {
                output: &mut *self.output,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct DoclingPageSeed<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> DeserializeSeed<'de> for DoclingPageSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.output.observe_page::<D::Error>()?;
        deserializer.deserialize_map(DoclingPageVisitor {
            output: self.output,
        })
    }
}

struct DoclingPageVisitor<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> Visitor<'de> for DoclingPageVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Docling page object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut text_seen = false;
        while let Some(field) = map.next_key_seed(DoclingFieldSeed)? {
            if matches!(field, DoclingField::Text) && !text_seen {
                text_seen = true;
                map.next_value_seed(DoclingTextSeed {
                    output: &mut *self.output,
                    target: DoclingTextTarget::Pages,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct DoclingContentSeed<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> DeserializeSeed<'de> for DoclingContentSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(DoclingContentVisitor {
            output: self.output,
        })
    }
}

struct DoclingContentVisitor<'a> {
    output: &'a mut DoclingOutputAccumulator,
}

impl<'de> Visitor<'de> for DoclingContentVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a legacy Docling content object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut text_seen = false;
        while let Some(field) = map.next_key_seed(DoclingFieldSeed)? {
            if matches!(field, DoclingField::Text) && !text_seen {
                text_seen = true;
                map.next_value_seed(DoclingTextSeed {
                    output: &mut *self.output,
                    target: DoclingTextTarget::Content,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct DoclingTextSeed<'a> {
    output: &'a mut DoclingOutputAccumulator,
    target: DoclingTextTarget,
}

impl<'de> DeserializeSeed<'de> for DoclingTextSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(DoclingTextVisitor {
            output: self.output,
            target: self.target,
        })
    }
}

struct DoclingTextVisitor<'a> {
    output: &'a mut DoclingOutputAccumulator,
    target: DoclingTextTarget,
}

impl<'de> Visitor<'de> for DoclingTextVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Docling text string or null")
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        self.output.append_borrowed(self.target, value)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<(), E>
    where
        E: de::Error,
    {
        self.output.append_borrowed(self.target, value)
    }

    fn visit_string<E>(self, value: String) -> Result<(), E>
    where
        E: de::Error,
    {
        self.output.append_owned(self.target, value)
    }

    fn visit_none<E>(self) -> Result<(), E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

fn parse_docling_output_with_limits(
    stdout: &[u8],
    limits: DoclingParseLimits,
) -> Result<(String, usize), String> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|error| format!("Docling output is not valid UTF-8: {error}"))?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok((String::new(), 0));
    }

    let mut output = DoclingOutputAccumulator::new(limits);
    let mut deserializer = serde_json::Deserializer::from_str(trimmed);
    let parsed = DoclingOutputSeed {
        output: &mut output,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    if let Some(error) = output.limit_error.take() {
        return Err(error);
    }
    if parsed.is_ok() {
        if let Some(extraction) = output.into_extraction() {
            return Ok(extraction);
        }
    } else {
        drop(output);
    }

    if trimmed.len() > limits.max_text_bytes {
        return Err(format!(
            "raw Docling output exceeds the {}-byte parser limit",
            limits.max_text_bytes
        ));
    }
    let mut text = String::new();
    text.try_reserve(trimmed.len())
        .map_err(|error| format!("reserve bounded raw Docling output: {error}"))?;
    text.push_str(trimmed);
    Ok((text, 1))
}

fn ext_from_mime(mime: &str) -> &'static str {
    match mime {
        "application/pdf" => ".pdf",
        m if m.contains("wordprocessingml") => ".docx",
        m if m.contains("presentationml") => ".pptx",
        m if m.contains("spreadsheetml") => ".xlsx",
        m if m.contains("opendocument.text") => ".odt",
        m if m.contains("opendocument.spreadsheet") => ".ods",
        m if m.contains("opendocument.presentation") => ".odp",
        "application/epub+zip" => ".epub",
        "application/rtf" => ".rtf",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/webp" => ".webp",
        _ => ".bin",
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    const DOCLING_SUPERVISOR_TEST_ROLE: &str = "NEOTH_TEST_DOCLING_SUPERVISOR_ROLE";
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    const DOCLING_SUPERVISOR_PID_PATH: &str = "NEOTH_TEST_DOCLING_SUPERVISOR_PID_PATH";
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    const DOCLING_SUPERVISOR_TEST_NAME: &str =
        "media::docling::tests::supervisor_survives_caller_cancellation_and_contains_descendants";

    #[test]
    fn parse_pages_array() {
        let json = r#"{"pages":[{"text":"hello world"},{"text":"second page"}]}"#;
        let (text, pages) = parse_docling_output(json.as_bytes()).unwrap();
        assert_eq!(pages, 2);
        assert!(text.contains("hello world"));
        assert!(text.contains("second page"));
    }

    #[test]
    fn parse_content_text_fallback() {
        let json = r#"{"content":{"text":"legacy format body"}}"#;
        let (text, pages) = parse_docling_output(json.as_bytes()).unwrap();
        assert_eq!(pages, 1);
        assert!(text.contains("legacy format body"));
    }

    #[test]
    fn parse_plain_text_fallback() {
        let raw = "# Markdown output\n\nsome content";
        let (text, pages) = parse_docling_output(raw.as_bytes()).unwrap();
        assert_eq!(pages, 1);
        assert!(text.contains("Markdown output"));
    }

    #[test]
    fn parse_empty_input_returns_zero_pages() {
        let (text, pages) = parse_docling_output(b"   ").unwrap();
        assert_eq!(pages, 0);
        assert!(text.is_empty());
    }

    #[test]
    fn parser_rejects_many_tiny_pages_before_unbounded_work() {
        let mut json = String::from("{\"pages\":[");
        for index in 0..=4096 {
            if index != 0 {
                json.push(',');
            }
            json.push_str("{\"text\":\"x\"}");
        }
        json.push_str("]}");
        let error = parse_docling_output_with_limits(
            json.as_bytes(),
            DoclingParseLimits {
                max_page_count: 4096,
                max_text_bytes: 64 * 1024,
            },
        )
        .expect_err("the 4097th page must fail before it is deserialized");
        assert!(error.contains("4096-page parser limit"));
    }

    #[test]
    fn parser_rejects_oversized_recognized_text_without_truncating() {
        let json = br#"{"pages":[{"text":"0123456789"}]}"#;
        let error = parse_docling_output_with_limits(
            json,
            DoclingParseLimits {
                max_page_count: 8,
                max_text_bytes: 8,
            },
        )
        .expect_err("recognized text over the cap must not become a partial extraction");
        assert!(error.contains("8-byte parser limit"));
    }

    #[test]
    fn parser_enforces_the_text_cap_cumulatively_across_pages() {
        let json = br#"{"pages":[{"text":"abcd"},{"text":"efgh"}]}"#;
        let error = parse_docling_output_with_limits(
            json,
            DoclingParseLimits {
                max_page_count: 8,
                max_text_bytes: 9,
            },
        )
        .expect_err("page separators and every accepted page must share one byte budget");
        assert!(error.contains("9-byte parser limit"));
    }

    #[test]
    fn parser_skips_large_nested_unknown_fields_without_a_value_tree() {
        let ignored_blob = "z".repeat(64 * 1024);
        let json = format!(
            "{{\"unknown\":{{\"nested\":[{{\"blob\":\"{ignored_blob}\"}}]}},\
             \"pages\":[{{\"text\":\"hello\"}}]}}"
        );
        let (text, pages) = parse_docling_output_with_limits(
            json.as_bytes(),
            DoclingParseLimits {
                max_page_count: 8,
                max_text_bytes: 8,
            },
        )
        .unwrap();
        assert_eq!(text, "hello");
        assert_eq!(pages, 1);
    }

    #[test]
    fn raw_output_fallback_obeys_the_same_text_cap() {
        let error = parse_docling_output_with_limits(
            b"plain text",
            DoclingParseLimits {
                max_page_count: 8,
                max_text_bytes: 8,
            },
        )
        .expect_err("raw fallback must never clone output past the extraction cap");
        assert!(error.contains("raw Docling output exceeds"));
    }

    #[test]
    fn parser_source_has_streaming_and_allocation_gates() {
        let source = include_str!("docling.rs");
        let parser_start = source
            .find("fn parse_docling_output(stdout:")
            .expect("Docling parser");
        let parser_end = source[parser_start..]
            .find("fn ext_from_mime")
            .map(|offset| parser_start + offset)
            .expect("end of Docling parser");
        let parser = &source[parser_start..parser_end];
        let value_tree = ["serde_json::", "Value"].concat();
        let pages_vec = ["Vec<", "&str>"].concat();
        let joined_pages = [".", "join(\"\\n\\n\")"].concat();
        assert!(!parser.contains(&value_tree));
        assert!(!parser.contains(&pages_vec));
        assert!(!parser.contains(&joined_pages));
        assert!(parser.contains("DeserializeSeed"));
        assert!(parser.contains("IgnoredAny"));
        assert!(parser.contains("try_reserve"));
        assert!(parser.contains("max_page_count"));
        assert!(parser.contains("max_text_bytes"));
    }

    #[test]
    fn ext_from_mime_covers_main_types() {
        assert_eq!(ext_from_mime("application/pdf"), ".pdf");
        assert_eq!(
            ext_from_mime(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            ".docx"
        );
        assert_eq!(ext_from_mime("image/png"), ".png");
        assert_eq!(ext_from_mime("application/octet-stream"), ".bin");
    }

    #[test]
    fn docling_input_limits_are_kind_specific_and_fail_closed() {
        assert_eq!(docling_input_limit(AssetKind::Image), 16 * 1024 * 1024);
        assert_eq!(docling_input_limit(AssetKind::Document), 64 * 1024 * 1024);
        assert!(ensure_docling_input_size(16, 16).is_ok());
        assert!(ensure_docling_input_size(17, 16).is_err());
    }

    #[test]
    fn safe_extension_never_carries_path_or_control_syntax() {
        let asset = Asset::Path {
            kind: AssetKind::Document,
            mime: "application/octet-stream".into(),
            path: PathBuf::from("report.DOCX"),
        };
        assert_eq!(safe_docling_extension(&asset), ".docx");

        let rejected = Asset::Path {
            kind: AssetKind::Document,
            mime: "application/rtf".into(),
            path: PathBuf::from("report.bad%0a"),
        };
        assert_eq!(safe_docling_extension(&rejected), ".rtf");
    }

    #[test]
    fn path_snapshot_enforces_actual_read_limit() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("source.pdf");
        std::fs::write(&source, b"12345").unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let target = target_dir.path().join("snapshot.pdf");

        let error = copy_docling_input_snapshot(&source, &target, 4)
            .expect_err("limit+1 sentinel must reject an oversized source");
        assert!(error.to_string().contains("input exceeds 4 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn path_snapshot_rejects_symlink_inputs() {
        use std::os::unix::fs::symlink;

        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("source.pdf");
        let link = source_dir.path().join("linked.pdf");
        std::fs::write(&source, b"%PDF").unwrap();
        symlink(&source, &link).unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let target = target_dir.path().join("snapshot.pdf");

        assert!(
            copy_docling_input_snapshot(&link, &target, 16).is_err(),
            "Docling must never follow an operator-controlled link"
        );
    }

    #[test]
    fn stderr_diagnostic_is_single_line_sanitized_and_bounded() {
        let input = format!("\u{1b}[31msecret\u{1b}[0m\n{}\u{7}", "x".repeat(700));
        let diagnostic = sanitized_diagnostic(input.as_bytes());
        assert!(!diagnostic.contains('\u{1b}'));
        assert!(!diagnostic.contains('\n'));
        assert!(!diagnostic.contains('\u{7}'));
        assert!(diagnostic.chars().count() <= 512);
    }

    #[tokio::test]
    async fn inherited_stderr_pipe_cannot_outlive_the_drain_deadline() {
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
            Vec::new()
        });
        let started = std::time::Instant::now();
        let error = collect_stderr_task_with_timeout(task, Duration::from_millis(20))
            .await
            .expect_err("a non-terminating pipe task must fail visibly");
        assert!(error.contains("exceeded"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cleanup_never_uses_tokios_unbounded_kill_wait_helper() {
        let source = include_str!("docling.rs");
        let unbounded_kill_wait = [".kill()", ".await"].concat();
        let start_kill = ["child.", "start_kill()"].concat();
        let bounded_wait = ["timeout(timeout, ", "child.wait())"].concat();
        assert!(!source.contains(&unbounded_kill_wait));
        assert!(source.contains(&start_kill));
        assert!(source.contains(&bounded_wait));
    }

    #[test]
    fn snapshot_creation_stays_inside_the_detached_lifecycle_owner() {
        let source = include_str!("docling.rs");
        let spawn_needle = ["tokio::spawn(", "run_owned_docling_supervisor"].concat();
        let owner_needle = ["async fn run_owned_", "docling_supervisor"].concat();
        let snapshot_needle = ["prepare_docling_input(", "&input).await"].concat();
        let prepare_needle = ["prepare_docling_", "input"].concat();
        let spawn = source
            .find(&spawn_needle)
            .expect("extractor must detach the complete Docling lifecycle");
        let owner = source
            .find(&owner_needle)
            .expect("owned Docling supervisor");
        let snapshot = source[owner..]
            .find(&snapshot_needle)
            .map(|offset| owner + offset)
            .expect("owned supervisor must create the private snapshot");
        assert!(spawn < owner && owner < snapshot);
        assert!(
            !source[spawn..owner].contains(&prepare_needle),
            "caller frame must not create a cancellation-sensitive private snapshot"
        );
        let caller_wait = ["DoclingCallerWaitGuard::", "armed()"].concat();
        let cancellation_log = ["detached supervisor retains ", "the permit"].concat();
        assert!(source.contains(&caller_wait));
        assert!(source.contains(&cancellation_log));
    }

    #[test]
    fn unix_docling_cleanup_pins_leader_until_group_proof_and_disarms_before_reap() {
        let source = include_str!("docling.rs");
        let wait_without_reap = ["libc::WEXITED | libc::WNOHANG | libc::", "WNOWAIT"].concat();
        assert!(source.contains(&wait_without_reap));
        assert!(source.contains("fn docling_terminal_without_reap("));
        assert!(source.contains("process_tree_is_empty_except_leader"));
        assert!(source.contains("refusing to signal a numeric Docling PGID after leader reap"));

        let cleanup_start = source
            .find(&["async fn terminate_docling_", "tree_bounded("].concat())
            .expect("tree cleanup helper");
        let windows_cleanup = source[cleanup_start..]
            .find("#[cfg(not(any(target_os = \"linux\", target_os = \"macos\")))]")
            .map(|offset| cleanup_start + offset)
            .expect("platform cleanup split");
        let cleanup = &source[cleanup_start..windows_cleanup];
        let tree_kill = cleanup
            .find("containment.terminate_tree(exit_status.is_some())")
            .expect("identity-safe process-group termination");
        let empty_proof = cleanup
            .find("containment.process_tree_is_empty_except_leader()")
            .expect("bounded group-membership proof");
        let disarm = cleanup
            .find("containment.disarm()")
            .expect("numeric PGID backstop disarm");
        let direct_reap = cleanup.find("child.try_wait()").expect("direct child reap");
        assert!(tree_kill < empty_proof && empty_proof < disarm && disarm < direct_reap);
    }

    #[test]
    fn windows_docling_process_is_resumed_only_after_job_assignment() {
        let source = include_str!("docling.rs");
        let suspended = ["creation_flags(CREATE_SUSPENDED", " | CREATE_NO_WINDOW)"].concat();
        let assigned = ["self.job.", "assign(child)?;"].concat();
        let resumed = ["containment.", "resume_child(&child)"].concat();
        let native_resume = ["fn nt_resume_", "process("].concat();
        let job_query = ["QueryInformation", "JobObject("].concat();
        let active_zero_proof = ["Ok(info.", "ActiveProcesses)"].concat();
        assert!(source.contains(&suspended));
        assert!(source.contains(&assigned));
        assert!(source.contains(&resumed));
        assert!(source.contains(&native_resume));
        assert!(source.contains(&job_query));
        assert!(source.contains(&active_zero_proof));

        let process_owner_start = source
            .find(&["async fn run_docling_", "supervisor("].concat())
            .expect("process supervisor");
        let process_owner_end = source[process_owner_start..]
            .find(&["async fn finish_docling_", "without_child("].concat())
            .map(|offset| process_owner_start + offset)
            .expect("end of process supervisor");
        let process_owner = &source[process_owner_start..process_owner_end];
        let configured_at = process_owner
            .find(&["DoclingContainmentSetup::", "configure(&mut command)"].concat())
            .expect("containment configuration");
        let spawned_at = process_owner
            .find(&["command.", "spawn()"].concat())
            .expect("suspended spawn");
        let assigned_at = process_owner
            .find(&["containment_setup.", "activate(&child)"].concat())
            .expect("Job Object assignment");
        let resumed_at = process_owner
            .find(&resumed)
            .expect("post-assignment process resume");
        assert!(configured_at < spawned_at && spawned_at < assigned_at && assigned_at < resumed_at);
        assert!(
            process_owner[resumed_at..].contains("finish_docling_with_child"),
            "resume failure must enter verified tree/reap/temp cleanup"
        );

        let cleanup_start = source
            .find(&["async fn terminate_docling_", "tree_bounded("].concat())
            .expect("tree cleanup helper");
        let cleanup_end = source[cleanup_start..]
            .find(&["async fn terminate_direct_", "child_bounded("].concat())
            .map(|offset| cleanup_start + offset)
            .expect("end of tree cleanup helper");
        let cleanup = &source[cleanup_start..cleanup_end];
        let tree_kill = cleanup
            .rfind("containment.terminate_tree(exit_status.is_some())")
            .expect("tree termination");
        let direct_reap = cleanup
            .find("terminate_direct_child_bounded")
            .expect("direct child reap");
        let empty_proof = cleanup
            .find("containment.wait_empty(timeout)")
            .expect("bounded empty-tree proof");
        let disarm = cleanup
            .rfind("containment.disarm()")
            .expect("post-proof disarm");
        assert!(tree_kill < direct_reap && direct_reap < empty_proof && empty_proof < disarm);

        let unsafe_send = ["unsafe impl Send for ", "WindowsDoclingJob"].concat();
        let unsafe_sync = ["unsafe impl Sync for ", "WindowsDoclingJob"].concat();
        assert!(
            !source.contains(&unsafe_send) && !source.contains(&unsafe_sync),
            "WindowsDoclingJob must use std's owned handle traits, not local unsafe impls"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_survives_caller_cancellation_and_contains_descendants() {
        match std::env::var(DOCLING_SUPERVISOR_TEST_ROLE).as_deref() {
            Ok("grandchild") => {
                std::thread::sleep(Duration::from_secs(30));
                panic!("Docling containment fixture grandchild survived its supervisor");
            }
            Ok("worker") => {
                let pid_path = std::env::var_os(DOCLING_SUPERVISOR_PID_PATH)
                    .map(PathBuf::from)
                    .expect("worker fixture PID path");
                let mut grandchild = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", DOCLING_SUPERVISOR_TEST_NAME, "--nocapture"])
                    .env(DOCLING_SUPERVISOR_TEST_ROLE, "grandchild")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn Docling containment grandchild");
                std::fs::write(&pid_path, grandchild.id().to_string())
                    .expect("publish Docling containment grandchild PID");
                std::thread::sleep(Duration::from_millis(250));
                // Deliberately detach the grandchild. The production
                // process-group/Job Object, not this fixture handle, must kill it.
                let _ = grandchild.try_wait();
                return;
            }
            Ok(other) => panic!("unexpected Docling supervisor test role: {other}"),
            Err(_) => {}
        }

        let tempfile_guard =
            crate::util::private_temp::directory(".neoth-docling-supervisor-test-").unwrap();
        let work_tree = tempfile_guard.path().to_path_buf();
        let pid_path = work_tree.join("grandchild.pid");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", DOCLING_SUPERVISOR_TEST_NAME, "--nocapture"])
            .env(DOCLING_SUPERVISOR_TEST_ROLE, "worker")
            .env(DOCLING_SUPERVISOR_PID_PATH, &pid_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let permit = acquire_docling_work_permit().await.unwrap();
        let limits = DoclingRunLimits {
            work_timeout: Duration::from_secs(5),
            reap_timeout: Duration::from_secs(5),
            pipe_timeout: Duration::from_secs(5),
            max_stdout_bytes: 1024 * 1024,
        };
        let supervisor = tokio::spawn(run_docling_supervisor(
            command,
            tempfile_guard,
            permit,
            AssetKind::Document,
            limits,
        ));
        // Match the production extraction frame: aborting this waiter drops
        // the supervisor JoinHandle but must not abort the supervisor task.
        let waiter = tokio::spawn(supervisor);

        let grandchild_pid = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(value) = tokio::fs::read_to_string(&pid_path).await
                    && let Ok(pid) = value.trim().parse::<u32>()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture published descendant PID");
        waiter.abort();
        let _ = waiter.await;

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if !work_tree.exists() && !test_process_is_live(grandchild_pid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("detached supervisor reaped the tree and removed its private work directory");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_process_is_live(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[cfg(windows)]
    fn test_process_is_live(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // SAFETY: OpenProcess consumes a scalar PID and returns an owned handle.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0_u32;
        // SAFETY: `handle` is live and `exit_code` is writable for this call.
        let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
        // SAFETY: this function owns the handle returned above.
        unsafe { CloseHandle(handle) };
        queried && exit_code == STILL_ACTIVE as u32
    }

    #[tokio::test]
    async fn docling_returns_unsupported_when_disabled() {
        let extractor = DoclingExtractor::new(false);
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"%PDF-1.4".to_vec(),
        };
        let result = extractor.extract(&asset).await;
        assert!(matches!(result, Err(ExtractionError::Unsupported { .. })));
    }

    #[tokio::test]
    async fn docling_returns_unsupported_for_audio() {
        let extractor = DoclingExtractor::new(true);
        let asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: vec![],
        };
        let result = extractor.extract(&asset).await;
        // Audio is always Unsupported even when Docling is enabled.
        assert!(
            matches!(result, Err(ExtractionError::Unsupported { .. })),
            "expected Unsupported for Audio kind, got {result:?}"
        );
    }
}
