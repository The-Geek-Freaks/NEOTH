//! PDF backend — R-9 Phase 2.
//!
//! Uses `pdf-extract` (pure Rust) for text extraction. Limitations:
//!   - No form-field reading (PDF AcroForm).
//!   - No OCR (image-only PDFs return empty text).
//!   - No layout preservation — pages become whitespace-separated text.
//!
//! Form editing is not exposed: the previous feature-gated scaffold was a
//! zero-consumer stub that failed even when compiled and has been removed.

use std::io::{Read, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::time::Duration;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Parsing bounds are enforced inside the extractor as well as at channel/CLI
/// admission. Other callers can construct an [`Asset`] directly, so the media
/// backend must remain safe on its own.
const MAX_PDF_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PDF_OBJECTS: usize = 250_000;
const MAX_PDF_PAGES: usize = 2_000;
const MAX_PDF_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PDF_PATH_BYTES: usize = 32 * 1024;
const PDF_WORKER_MODE_ENV: &str = "NEOTH_INTERNAL_PDF_WORKER_V1";
const PDF_WORKER_PATH_ENV: &str = "NEOTH_INTERNAL_PDF_PATH";
#[cfg(windows)]
const PDF_WORKER_JOB_ENV: &str = "NEOTH_INTERNAL_PDF_JOB";
const PDF_WORKER_MODE_VALUE: &str = "parse";
const PDF_WORKER_INPUT_MAGIC: &[u8; 8] = b"NTHPDI01";
const PDF_WORKER_INPUT_KIND_BYTES: u8 = 1;
const PDF_WORKER_INPUT_KIND_PATH: u8 = 2;
const PDF_WORKER_INPUT_HEADER_BYTES: usize =
    PDF_WORKER_INPUT_MAGIC.len() + size_of::<u8>() + size_of::<u64>();
const PDF_WORKER_MAGIC: &[u8; 8] = b"NTHPDF01";
const PDF_WORKER_HEADER_BYTES: usize = PDF_WORKER_MAGIC.len() + 4 * size_of::<u64>();
const PDF_WORKER_STDOUT_CAP_BYTES: usize = PDF_WORKER_HEADER_BYTES + MAX_PDF_TEXT_BYTES;
#[cfg(not(test))]
const PDF_WORKER_STDERR_CAP_BYTES: usize = 4 * 1024;
#[cfg(not(test))]
const PDF_WORKER_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const PDF_WORKER_WORK_TIMEOUT: Duration = Duration::from_secs(27);
#[cfg(not(test))]
const PDF_WORKER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(not(test))]
const PDF_WORKER_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(any(not(test), unix))]
const PDF_WORKER_CPU_SECONDS: u64 = 20;
#[cfg(any(not(test), unix))]
const PDF_WORKER_MEMORY_BYTES: usize = 768 * 1024 * 1024;
#[cfg(unix)]
const PDF_WORKER_NOFILE_LIMIT: u64 = 32;
#[cfg(unix)]
const PDF_WORKER_PROCESS_LIMIT: u64 = 1;
#[cfg(not(test))]
const PDF_WORKER_CONCURRENCY: usize = 1;

#[cfg(not(test))]
static PDF_WORKER_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(PDF_WORKER_CONCURRENCY);
#[cfg(not(test))]
static PDF_WORKER_BUDGET_POISONED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub struct PdfExtractor;

#[async_trait::async_trait]
impl MediaExtractor for PdfExtractor {
    fn name(&self) -> &'static str {
        "pdf"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Pdf {
            return Err(ExtractionError::Unsupported {
                backend: "pdf",
                got: asset.kind(),
            });
        }
        extract_pdf_asset(asset).await
    }
}

#[cfg(test)]
async fn extract_pdf_asset(asset: &Asset) -> Result<Extraction, ExtractionError> {
    // Unit tests exercise parser/output behaviour in process. Production
    // callers always take the isolated worker path below.
    preflight_pdf_asset(asset)?;
    let payload = asset.clone();
    tokio::task::spawn_blocking(move || {
        let bytes = read_pdf_bytes(&payload)?;
        parse_pdf_bytes(bytes).map(ParsedPdf::into_extraction)
    })
    .await
    .map_err(|e| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("join error: {e}"),
    })?
}

#[cfg(not(test))]
async fn extract_pdf_asset(asset: &Asset) -> Result<Extraction, ExtractionError> {
    extract_pdf_isolated(asset).await
}

struct ParsedPdf {
    text: String,
    object_count: usize,
    page_count: usize,
    input_bytes: usize,
}

impl ParsedPdf {
    fn into_extraction(self) -> Extraction {
        let stats = compute_stats(&self.text);
        Extraction {
            text: self.text,
            metadata: serde_json::json!({
                "extractor": "pdf-extract-isolated",
                "char_count": stats.chars,
                "word_count": stats.words,
                "line_count": stats.lines,
                "object_count": self.object_count,
                "page_count": self.page_count,
                "input_bytes": self.input_bytes,
                "output_cap_bytes": MAX_PDF_TEXT_BYTES,
            }),
        }
    }
}

fn parse_pdf_bytes(bytes: Vec<u8>) -> Result<ParsedPdf, ExtractionError> {
    enforce_pdf_byte_ceiling(bytes.len() as u64)?;
    let input_bytes = bytes.len();
    let mut document =
        pdf_extract::Document::load_mem(&bytes).map_err(|e| ExtractionError::Backend {
            backend: "pdf",
            reason: format!("parse PDF: {e}"),
        })?;
    if document.is_encrypted() {
        document.decrypt("").map_err(|e| ExtractionError::Backend {
            backend: "pdf",
            reason: format!("decrypt PDF: {e}"),
        })?;
    }

    let object_count = document.objects.len();
    if object_count > MAX_PDF_OBJECTS {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!(
                "PDF has {object_count} objects, exceeding the {MAX_PDF_OBJECTS}-object work cap"
            ),
        });
    }
    let page_count = document.get_pages().len();
    if page_count > MAX_PDF_PAGES {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!(
                "PDF has {page_count} pages, exceeding the {MAX_PDF_PAGES}-page work cap"
            ),
        });
    }

    // `pdf-extract` exposes its streaming output device. Back it with a
    // fail-closed writer so parsing stops as soon as extracted text crosses
    // the bound instead of first materialising an unbounded String.
    let mut sink = CappedWriter::new(MAX_PDF_TEXT_BYTES);
    let extraction_result = {
        let writer: &mut dyn Write = &mut sink;
        let mut output = pdf_extract::PlainTextOutput::new(writer);
        pdf_extract::output_doc(&document, &mut output)
    };
    if sink.exceeded {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!("extracted text exceeds the {MAX_PDF_TEXT_BYTES}-byte output cap"),
        });
    }
    extraction_result.map_err(|e| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("extract PDF text: {e}"),
    })?;
    let text = String::from_utf8(sink.bytes).map_err(|e| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("extracted text is not UTF-8: {e}"),
    })?;
    Ok(ParsedPdf {
        text,
        object_count,
        page_count,
        input_bytes,
    })
}

fn read_pdf_bytes(asset: &Asset) -> Result<Vec<u8>, ExtractionError> {
    match asset {
        Asset::Bytes { data, .. } => {
            enforce_pdf_byte_ceiling(data.len() as u64)?;
            Ok(data.clone())
        }
        Asset::Path { path, .. } => {
            let mut file = open_pdf_input_no_follow(path)
                .map_err(|e| ExtractionError::Io(format!("open PDF input: {e}")))?;
            let before = file
                .metadata()
                .map_err(|e| ExtractionError::Io(format!("inspect PDF input: {e}")))?;
            if !before.is_file() || pdf_metadata_is_link_like(&before) {
                return Err(ExtractionError::Backend {
                    backend: "pdf",
                    reason: "PDF input must be a regular non-link file".into(),
                });
            }
            enforce_pdf_byte_ceiling(before.len())?;
            let before_modified = before.modified().ok();
            let mut bytes = Vec::with_capacity(before.len() as usize);
            std::io::Read::by_ref(&mut file)
                .take(MAX_PDF_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| ExtractionError::Io(format!("read PDF input: {e}")))?;
            enforce_pdf_byte_ceiling(bytes.len() as u64)?;
            let after = file
                .metadata()
                .map_err(|e| ExtractionError::Io(format!("re-inspect PDF input: {e}")))?;
            if before.len() != after.len()
                || before_modified != after.modified().ok()
                || bytes.len() as u64 != before.len()
            {
                return Err(ExtractionError::Backend {
                    backend: "pdf",
                    reason: "PDF input changed while it was being read".into(),
                });
            }
            Ok(bytes)
        }
    }
}

fn open_pdf_input_no_follow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
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

fn pdf_metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
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

fn enforce_pdf_byte_ceiling(len: u64) -> Result<(), ExtractionError> {
    if len > MAX_PDF_BYTES {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!("input {len} bytes exceeds the {MAX_PDF_BYTES}-byte cap"),
        });
    }
    Ok(())
}

fn preflight_pdf_asset(asset: &Asset) -> Result<(), ExtractionError> {
    match asset {
        Asset::Bytes { data, .. } => enforce_pdf_byte_ceiling(data.len() as u64),
        Asset::Path { path, .. } => {
            let path_bytes = worker_path_len(path);
            if path_bytes > MAX_PDF_PATH_BYTES {
                return Err(ExtractionError::Backend {
                    backend: "pdf",
                    reason: format!(
                        "PDF path encoding is {path_bytes} bytes, exceeding the \
                         {MAX_PDF_PATH_BYTES}-byte worker transport cap"
                    ),
                });
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
fn worker_path_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt as _;

    path.as_os_str().as_bytes().len()
}

#[cfg(windows)]
fn worker_path_len(path: &Path) -> usize {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str().encode_wide().count().saturating_mul(2)
}

#[cfg(not(any(unix, windows)))]
fn worker_path_len(path: &Path) -> usize {
    path.as_os_str().to_string_lossy().len()
}

#[cfg(not(test))]
async fn extract_pdf_isolated(asset: &Asset) -> Result<Extraction, ExtractionError> {
    // O(1) borrowed admission happens before the process-wide budget and, most
    // importantly, before any attacker-controlled Vec or path is cloned.
    preflight_pdf_asset(asset)?;
    let started = tokio::time::Instant::now();
    let work_deadline = started + PDF_WORKER_WORK_TIMEOUT;
    let total_deadline = started + PDF_WORKER_TOTAL_TIMEOUT;
    if PDF_WORKER_BUDGET_POISONED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker budget is poisoned after unverified cleanup".into(),
        });
    }
    let permit = tokio::time::timeout_at(work_deadline, PDF_WORKER_BUDGET.acquire())
        .await
        .map_err(|_| ExtractionError::Backend {
            backend: "pdf",
            reason: if PDF_WORKER_BUDGET_POISONED.load(std::sync::atomic::Ordering::Acquire) {
                "isolated PDF worker budget is poisoned after unverified cleanup".into()
            } else {
                "isolated PDF worker queue exceeded its total work deadline".into()
            },
        })?
        .map_err(|_| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker concurrency budget is closed".into(),
        })?;

    let executable = resolve_verified_neoth_executable()?;
    let mut command = tokio::process::Command::new(executable);
    command
        .env_clear()
        .env(PDF_WORKER_MODE_ENV, PDF_WORKER_MODE_VALUE)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Asset::Path { path, .. } = asset {
        command.env(PDF_WORKER_PATH_ENV, path);
    }
    let containment_setup = PdfWorkerContainmentSetup::configure(&mut command)?;

    let mut child = command.spawn().map_err(|error| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("spawn isolated PDF worker: {error}"),
    })?;
    // From this point a child exists. This lease releases the only global
    // permit solely after direct-child reaping and process-tree-empty proof.
    // Every other Drop path poisons the budget closed for the process lifetime.
    let budget = PdfWorkerBudgetLease::new(permit);
    let containment = match containment_setup.activate(&child) {
        Ok(containment) => containment,
        Err(error) => {
            let _ = child.start_kill();
            drop(budget);
            return Err(error);
        }
    };
    let mut supervisor = PdfWorkerSupervisor::new(child, containment, budget);
    let stdout = supervisor.take_stdout()?;
    let stderr = supervisor.take_stderr()?;
    let stdout_task = tokio::spawn(read_bounded_worker_pipe(
        stdout,
        PDF_WORKER_STDOUT_CAP_BYTES,
    ));
    let stderr_task = tokio::spawn(read_bounded_worker_pipe(
        stderr,
        PDF_WORKER_STDERR_CAP_BYTES,
    ));

    let mut failure = match tokio::time::timeout_at(
        work_deadline,
        write_pdf_worker_request(supervisor.stdin_mut()?, asset),
    )
    .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("write isolated PDF worker input: {error}")),
        Err(_) => Some("isolated PDF worker input exceeded its work deadline".into()),
    };
    #[cfg(not(target_os = "macos"))]
    supervisor.close_stdin();

    if failure.is_none()
        && let Err(error) = supervisor.wait_for_terminal(work_deadline).await
    {
        failure = Some(error);
    }

    supervisor.close_stdin();
    let status = match supervisor.cleanup_and_disarm(total_deadline).await {
        Ok(status) => Some(status),
        Err(error) => {
            if let Some(reason) = &mut failure {
                reason.push_str("; cleanup: ");
                reason.push_str(&error);
            } else {
                failure = Some(format!(
                    "isolated PDF worker cleanup was not proven: {error}"
                ));
            }
            None
        }
    };

    let stdout_result = collect_pdf_worker_pipe(stdout_task, total_deadline, "stdout").await;
    let stderr_result = collect_pdf_worker_pipe(stderr_task, total_deadline, "stderr").await;

    if let Some(mut reason) = failure {
        if let Ok(stderr) = &stderr_result {
            let diagnostic = safe_worker_diagnostic(&String::from_utf8_lossy(stderr));
            if !diagnostic.is_empty() {
                reason.push_str("; worker: ");
                reason.push_str(&diagnostic);
            }
        }
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason,
        });
    }

    let stdout = stdout_result?;
    let stderr = stderr_result?;
    let status = status.ok_or_else(|| ExtractionError::Backend {
        backend: "pdf",
        reason: "isolated PDF worker exited without a status".into(),
    })?;
    if !status.success() {
        let diagnostic = safe_worker_diagnostic(&String::from_utf8_lossy(&stderr));
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: if diagnostic.is_empty() {
                format!("isolated PDF worker failed with status {status}")
            } else {
                format!("isolated PDF worker failed with status {status}: {diagnostic}")
            },
        });
    }

    decode_worker_response(&stdout).map(ParsedPdf::into_extraction)
}

#[cfg(not(test))]
fn resolve_verified_neoth_executable() -> Result<PathBuf, ExtractionError> {
    let current = std::env::current_exe().map_err(|error| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("resolve isolated PDF worker executable: {error}"),
    })?;
    let expected_name = if cfg!(windows) { "neoth.exe" } else { "neoth" };
    let sibling = current.with_file_name(expected_name);
    let candidate = if executable_name_is_neoth(&current) {
        current.clone()
    } else if sibling.is_file() {
        sibling.clone()
    } else if cfg!(debug_assertions)
        && current
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "deps")
    {
        // Cargo integration tests execute from target/<profile>/deps while
        // binary targets live one directory above. Restrict this development
        // fallback to that exact layout; installed/release binaries continue
        // to require the current or adjacent signed distribution executable.
        current
            .parent()
            .and_then(Path::parent)
            .map(|profile_dir| profile_dir.join(expected_name))
            .unwrap_or(sibling)
    } else {
        sibling
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|error| ExtractionError::Backend {
            backend: "pdf",
            reason: format!(
                "verified sibling `{expected_name}` is unavailable for isolated PDF parsing \
                 (current executable {}): {error}",
                current.display()
            ),
        })?;
    let metadata = canonical
        .metadata()
        .map_err(|error| ExtractionError::Backend {
            backend: "pdf",
            reason: format!("inspect isolated PDF worker executable: {error}"),
        })?;
    if !metadata.is_file() || !executable_name_is_neoth(&canonical) {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!(
                "isolated PDF worker must be the current or sibling `{expected_name}` executable"
            ),
        });
    }
    Ok(canonical)
}

#[cfg(not(test))]
fn executable_name_is_neoth(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if cfg!(windows) {
        name.eq_ignore_ascii_case("neoth.exe")
    } else {
        name == "neoth"
    }
}

#[cfg(not(test))]
async fn write_pdf_worker_request(
    stdin: &mut tokio::process::ChildStdin,
    asset: &Asset,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let (kind, payload_len) = match asset {
        Asset::Bytes { data, .. } => (PDF_WORKER_INPUT_KIND_BYTES, data.len() as u64),
        Asset::Path { .. } => (PDF_WORKER_INPUT_KIND_PATH, 0),
    };
    let mut header = [0_u8; PDF_WORKER_INPUT_HEADER_BYTES];
    header[..PDF_WORKER_INPUT_MAGIC.len()].copy_from_slice(PDF_WORKER_INPUT_MAGIC);
    header[PDF_WORKER_INPUT_MAGIC.len()] = kind;
    header[PDF_WORKER_INPUT_MAGIC.len() + 1..].copy_from_slice(&payload_len.to_be_bytes());
    stdin.write_all(&header).await?;
    if let Asset::Bytes { data, .. } = asset {
        stdin.write_all(data).await?;
    }
    #[cfg(target_os = "macos")]
    {
        // Keep the write end open as the worker's parent/task-lifetime lease.
        // EOF is reserved for owner death or async cancellation.
        stdin.flush().await
    }
    #[cfg(not(target_os = "macos"))]
    {
        stdin.shutdown().await
    }
}

#[derive(Debug)]
enum PdfWorkerPipeError {
    Io(std::io::Error),
    LimitExceeded,
}

impl std::fmt::Display for PdfWorkerPipeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::LimitExceeded => formatter.write_str("pipe byte cap exceeded"),
        }
    }
}

impl std::error::Error for PdfWorkerPipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::LimitExceeded => None,
        }
    }
}

async fn read_bounded_worker_pipe<R>(
    mut reader: R,
    cap: usize,
) -> Result<Vec<u8>, PdfWorkerPipeError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut output = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(PdfWorkerPipeError::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if read > cap.saturating_sub(output.len()) {
            return Err(PdfWorkerPipeError::LimitExceeded);
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(not(test))]
async fn collect_pdf_worker_pipe(
    mut task: tokio::task::JoinHandle<Result<Vec<u8>, PdfWorkerPipeError>>,
    deadline: tokio::time::Instant,
    label: &'static str,
) -> Result<Vec<u8>, ExtractionError> {
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(Ok(bytes))) => Ok(bytes),
        Ok(Ok(Err(PdfWorkerPipeError::LimitExceeded))) => Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!("isolated PDF worker {label} exceeded its byte cap"),
        }),
        Ok(Ok(Err(PdfWorkerPipeError::Io(error)))) => Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!("read isolated PDF worker {label}: {error}"),
        }),
        Ok(Err(error)) => Err(ExtractionError::Backend {
            backend: "pdf",
            reason: format!("join isolated PDF worker {label} reader: {error}"),
        }),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ExtractionError::Backend {
                backend: "pdf",
                reason: format!("isolated PDF worker {label} drain exceeded the total deadline"),
            })
        }
    }
}

#[cfg(not(test))]
struct PdfWorkerBudgetLease {
    permit: Option<tokio::sync::SemaphorePermit<'static>>,
    verified_cleanup: bool,
}

#[cfg(not(test))]
impl PdfWorkerBudgetLease {
    fn new(permit: tokio::sync::SemaphorePermit<'static>) -> Self {
        Self {
            permit: Some(permit),
            verified_cleanup: false,
        }
    }

    fn release_after_verified_cleanup(mut self) {
        self.verified_cleanup = true;
    }
}

#[cfg(not(test))]
impl Drop for PdfWorkerBudgetLease {
    fn drop(&mut self) {
        if self.verified_cleanup {
            return;
        }
        PDF_WORKER_BUDGET_POISONED.store(true, std::sync::atomic::Ordering::Release);
        if let Some(permit) = self.permit.take() {
            // The only global permit must never become available after an
            // unverified cleanup. Forgetting it poisons admission fail-closed
            // until process restart, including runtime-shutdown cancellation.
            std::mem::forget(permit);
        }
    }
}

#[cfg(not(test))]
struct PdfWorkerSupervisor {
    child: Option<tokio::process::Child>,
    containment: Option<PdfWorkerContainment>,
    stdin: Option<tokio::process::ChildStdin>,
    budget: Option<PdfWorkerBudgetLease>,
    exit_status: Option<std::process::ExitStatus>,
}

#[cfg(not(test))]
impl PdfWorkerSupervisor {
    fn new(
        mut child: tokio::process::Child,
        containment: PdfWorkerContainment,
        budget: PdfWorkerBudgetLease,
    ) -> Self {
        let stdin = child.stdin.take();
        Self {
            child: Some(child),
            containment: Some(containment),
            stdin,
            budget: Some(budget),
            exit_status: None,
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("PDF worker supervisor always owns its child until drop")
    }

    fn stdin_mut(&mut self) -> Result<&mut tokio::process::ChildStdin, ExtractionError> {
        self.stdin.as_mut().ok_or_else(|| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker stdin pipe was not created".into(),
        })
    }

    fn take_stdout(&mut self) -> Result<tokio::process::ChildStdout, ExtractionError> {
        self.child_mut()
            .stdout
            .take()
            .ok_or_else(|| ExtractionError::Backend {
                backend: "pdf",
                reason: "isolated PDF worker stdout pipe was not created".into(),
            })
    }

    fn take_stderr(&mut self) -> Result<tokio::process::ChildStderr, ExtractionError> {
        self.child_mut()
            .stderr
            .take()
            .ok_or_else(|| ExtractionError::Backend {
                backend: "pdf",
                reason: "isolated PDF worker stderr pipe was not created".into(),
            })
    }

    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    async fn wait_for_terminal(&mut self, deadline: tokio::time::Instant) -> Result<(), String> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let child_pid = self
                .containment
                .as_ref()
                .expect("PDF worker containment remains armed while waiting")
                .leader_pid();
            wait_for_pdf_worker_terminal_without_reap(child_pid, deadline).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            match tokio::time::timeout_at(deadline, self.child_mut().wait()).await {
                Ok(Ok(status)) => {
                    self.exit_status = Some(status);
                    Ok(())
                }
                Ok(Err(error)) => Err(format!("wait for isolated PDF worker: {error}")),
                Err(_) => Err(format!(
                    "isolated PDF worker exceeded the {}-second total wall-clock limit",
                    PDF_WORKER_TOTAL_TIMEOUT.as_secs()
                )),
            }
        }
    }

    async fn cleanup_and_disarm(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<std::process::ExitStatus, String> {
        let containment = self
            .containment
            .take()
            .expect("PDF worker containment remains armed until cleanup proof");
        {
            let child = self
                .child
                .as_mut()
                .expect("PDF worker supervisor owns the direct child until cleanup");
            cleanup_pdf_worker(child, containment, &mut self.exit_status, deadline).await?;
        }

        let status = self
            .exit_status
            .take()
            .ok_or_else(|| "PDF worker cleanup completed without an exit status".to_string())?;
        self.budget
            .take()
            .expect("PDF worker budget remains owned until verified cleanup")
            .release_after_verified_cleanup();
        Ok(status)
    }
}

#[cfg(not(test))]
impl Drop for PdfWorkerSupervisor {
    fn drop(&mut self) {
        // Closing stdin first trips the macOS worker's parent/task-lifetime
        // lease. The explicit process-group/Job termination is the independent
        // second layer and covers cancellation before the worker arms its
        // watchdog.
        drop(self.stdin.take());

        let Some(budget) = self.budget.take() else {
            return;
        };
        let Some(mut child) = self.child.take() else {
            return;
        };
        let Some(containment) = self.containment.take() else {
            return;
        };
        let mut exit_status = self.exit_status.take();
        let _ = containment.terminate_tree(exit_status.is_some());
        if exit_status.is_none() {
            let _ = child.start_kill();
        }

        // Async functions can be cancelled at every await, but Drop cannot
        // await. The detached cleanup owns the budget lease. If the runtime
        // drops this future during shutdown, the lease Drop poisons admission
        // instead of releasing the permit before cleanup has been proven.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                let deadline = tokio::time::Instant::now() + PDF_WORKER_CLEANUP_TIMEOUT;
                match cleanup_pdf_worker(&mut child, containment, &mut exit_status, deadline).await
                {
                    Ok(()) => {
                        budget.release_after_verified_cleanup();
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "PDF worker detached cleanup was not proven; budget poisoned"
                        );
                    }
                }
            }));
        } else {
            tracing::error!("PDF worker cleanup lost its Tokio runtime; budget poisoned");
        }
        // With no live runtime, `budget` drops here and poisons the singleton
        // permit. The Job handle/kill_on_drop still provide best-effort kill,
        // but no future request can overlap an unproven cleanup.
    }
}

#[cfg(not(test))]
async fn cleanup_pdf_worker(
    child: &mut tokio::process::Child,
    containment: PdfWorkerContainment,
    exit_status: &mut Option<std::process::ExitStatus>,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    containment.terminate_tree(exit_status.is_some())?;

    loop {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let direct_child_terminal = pdf_worker_terminal_without_reap(containment.leader_pid())?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let direct_child_terminal = if exit_status.is_some() {
            true
        } else {
            match child.try_wait() {
                Ok(Some(status)) => {
                    *exit_status = Some(status);
                    true
                }
                Ok(None) => false,
                Err(error) => return Err(format!("inspect PDF worker before reap: {error}")),
            }
        };

        let tree_empty =
            direct_child_terminal && containment.process_tree_is_empty_except_leader()?;
        if direct_child_terminal && tree_empty {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                match child.try_wait() {
                    Ok(Some(status)) => *exit_status = Some(status),
                    Ok(None) => {
                        return Err(
                            "PDF worker terminal state vanished before identity-safe reap".into(),
                        );
                    }
                    Err(error) => return Err(format!("reap PDF worker: {error}")),
                }
            }
            return Ok(());
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(
                "PDF worker cleanup deadline expired before direct-child reap and tree-empty proof"
                    .into(),
            );
        }
        tokio::time::sleep_until((now + PDF_WORKER_CLEANUP_POLL_INTERVAL).min(deadline)).await;
    }
}

#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
async fn wait_for_pdf_worker_terminal_without_reap(
    child_pid: libc::pid_t,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    loop {
        if pdf_worker_terminal_without_reap(child_pid)? {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "isolated PDF worker exceeded the {}-second total wall-clock limit",
                PDF_WORKER_TOTAL_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep_until((now + PDF_WORKER_CLEANUP_POLL_INTERVAL).min(deadline)).await;
    }
}

#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
fn pdf_worker_terminal_without_reap(child_pid: libc::pid_t) -> Result<bool, String> {
    let wait_id = libc::id_t::try_from(child_pid)
        .map_err(|_| "PDF worker PID does not fit waitid identity".to_string())?;
    // SAFETY: zero is the required initial state for a WNOHANG siginfo_t, and
    // waitid writes only to this live object. WNOWAIT pins the zombie/PID so the
    // numeric PGID cannot be reused before tree termination and membership
    // proof complete.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
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
            "observe PDF worker terminal state without reaping: {error}"
        ));
    }
    // SAFETY: waitid initialized the SIGCHLD view of siginfo_t. WNOHANG leaves
    // si_pid zero when no matching child is terminal.
    Ok(unsafe { info.si_pid() } == child_pid)
}

/// Run the private PDF parser worker before normal CLI parsing.
///
/// This is intentionally environment-triggered instead of being a Clap
/// subcommand: it is an implementation detail used only by the parent process,
/// not a public CLI surface. The worker applies/verifies OS containment, waits
/// for the parent's post-containment stdin handshake, and writes one bounded
/// binary response to stdout.
pub fn run_internal_pdf_worker_if_requested() -> Option<Result<(), String>> {
    let mode = std::env::var_os(PDF_WORKER_MODE_ENV)?;
    if mode != std::ffi::OsStr::new(PDF_WORKER_MODE_VALUE) {
        return Some(Err("invalid internal PDF worker mode".into()));
    }

    let result = (|| {
        apply_pdf_worker_resource_limits()?;
        let request = read_pdf_worker_request()?;
        arm_pdf_worker_parent_liveness_watchdog()?;
        let bytes = request.into_bytes()?;
        let parsed =
            parse_pdf_bytes(bytes).map_err(|error| safe_worker_diagnostic(&error.to_string()))?;
        let response = encode_worker_response(&parsed)?;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        stdout
            .write_all(&response)
            .map_err(|error| format!("write internal PDF worker response: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("flush internal PDF worker response: {error}"))
    })();
    Some(result)
}

enum PdfWorkerRequest {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

impl PdfWorkerRequest {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Path(path) => {
                let asset = Asset::Path {
                    kind: AssetKind::Pdf,
                    mime: "application/pdf".into(),
                    path,
                };
                read_pdf_bytes(&asset).map_err(|error| safe_worker_diagnostic(&error.to_string()))
            }
        }
    }
}

fn read_pdf_worker_request() -> Result<PdfWorkerRequest, String> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut header = [0_u8; PDF_WORKER_INPUT_HEADER_BYTES];
    stdin
        .read_exact(&mut header)
        .map_err(|error| format!("read internal PDF worker handshake: {error}"))?;
    if &header[..PDF_WORKER_INPUT_MAGIC.len()] != PDF_WORKER_INPUT_MAGIC {
        return Err("invalid internal PDF worker handshake".into());
    }
    let kind = header[PDF_WORKER_INPUT_MAGIC.len()];
    let payload_len = u64::from_be_bytes(
        header[PDF_WORKER_INPUT_MAGIC.len() + 1..]
            .try_into()
            .map_err(|_| "invalid internal PDF worker length field")?,
    );

    // The parent sends the handshake only after process containment is active.
    // Verify that exact platform boundary before allocating or opening any
    // attacker-controlled payload.
    verify_pdf_worker_containment()?;

    let request = match kind {
        PDF_WORKER_INPUT_KIND_BYTES => {
            enforce_pdf_byte_ceiling(payload_len)
                .map_err(|error| safe_worker_diagnostic(&error.to_string()))?;
            let payload_len = usize::try_from(payload_len)
                .map_err(|_| "internal PDF worker payload does not fit this platform")?;
            let mut bytes = vec![0_u8; payload_len];
            stdin
                .read_exact(&mut bytes)
                .map_err(|error| format!("read internal PDF worker payload: {error}"))?;
            PdfWorkerRequest::Bytes(bytes)
        }
        PDF_WORKER_INPUT_KIND_PATH => {
            if payload_len != 0 {
                return Err("internal PDF path request carried an unexpected payload".into());
            }
            let path = std::env::var_os(PDF_WORKER_PATH_ENV)
                .ok_or_else(|| "internal PDF worker path is missing".to_string())?;
            let path = PathBuf::from(path);
            if worker_path_len(&path) > MAX_PDF_PATH_BYTES {
                return Err("internal PDF worker path exceeds its transport cap".into());
            }
            PdfWorkerRequest::Path(path)
        }
        _ => return Err("invalid internal PDF worker input kind".into()),
    };
    #[cfg(not(target_os = "macos"))]
    {
        let mut trailing = [0_u8; 1];
        if stdin
            .read(&mut trailing)
            .map_err(|error| format!("finish internal PDF worker input: {error}"))?
            != 0
        {
            return Err("internal PDF worker input contains trailing bytes".into());
        }
    }
    Ok(request)
}

#[cfg(target_os = "macos")]
fn arm_pdf_worker_parent_liveness_watchdog() -> Result<(), String> {
    verify_pdf_worker_process_group()?;

    // A fully written framed request leaves no readable bytes while the parent
    // owns the stdin write end. EOF, trailing data, or a pipe error at this
    // point means the lifetime lease is already invalid.
    let mut readiness = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    // SAFETY: `readiness` is valid writable storage for one pollfd and the
    // zero timeout performs a non-blocking state check.
    let poll_result = unsafe { libc::poll(&raw mut readiness, 1, 0) };
    if poll_result < 0 {
        return Err(format!(
            "inspect internal PDF worker parent-liveness lease: {}",
            std::io::Error::last_os_error()
        ));
    }
    if poll_result != 0 {
        return Err(
            "internal PDF worker parent-liveness lease is already closed or invalid".into(),
        );
    }

    // SAFETY: the dedicated process-group check above proved pid == pgid.
    let process_group = unsafe { libc::getpgrp() };
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    let _watchdog = std::thread::Builder::new()
        .name("neoth-pdf-parent-watch".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            if ready_tx.send(()).is_err() {
                terminate_macos_pdf_worker_group(process_group);
            }
            let mut trailing = [0_u8; 1];
            loop {
                match stdin.read(&mut trailing) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    // EOF is parent death/cancellation. Any byte is invalid
                    // trailing input. Every terminal condition fails closed.
                    _ => terminate_macos_pdf_worker_group(process_group),
                }
            }
        })
        .map_err(|error| format!("start internal PDF worker parent watchdog: {error}"))?;
    ready_rx
        .recv()
        .map_err(|error| format!("arm internal PDF worker parent watchdog: {error}"))
}

#[cfg(target_os = "macos")]
fn terminate_macos_pdf_worker_group(process_group: libc::pid_t) -> ! {
    // SAFETY: the worker is the positive leader of its dedicated process
    // group. Negating the pgid targets the worker and every descendant that has
    // not deliberately escaped the group; RLIMIT_NPROC independently prevents
    // the parser from creating such descendants.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
        libc::_exit(127);
    }
}

#[cfg(not(target_os = "macos"))]
fn arm_pdf_worker_parent_liveness_watchdog() -> Result<(), String> {
    Ok(())
}

fn encode_worker_response(parsed: &ParsedPdf) -> Result<Vec<u8>, String> {
    if parsed.text.len() > MAX_PDF_TEXT_BYTES {
        return Err("internal PDF worker text exceeds its protocol cap".into());
    }
    let mut response = Vec::with_capacity(PDF_WORKER_HEADER_BYTES + parsed.text.len());
    response.extend_from_slice(PDF_WORKER_MAGIC);
    response.extend_from_slice(&(parsed.object_count as u64).to_be_bytes());
    response.extend_from_slice(&(parsed.page_count as u64).to_be_bytes());
    response.extend_from_slice(&(parsed.input_bytes as u64).to_be_bytes());
    response.extend_from_slice(&(parsed.text.len() as u64).to_be_bytes());
    response.extend_from_slice(parsed.text.as_bytes());
    Ok(response)
}

fn decode_worker_response(response: &[u8]) -> Result<ParsedPdf, ExtractionError> {
    if response.len() < PDF_WORKER_HEADER_BYTES
        || &response[..PDF_WORKER_MAGIC.len()] != PDF_WORKER_MAGIC
    {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker returned an invalid protocol header".into(),
        });
    }
    let mut offset = PDF_WORKER_MAGIC.len();
    let mut next_u64 = || {
        let value = u64::from_be_bytes(
            response[offset..offset + size_of::<u64>()]
                .try_into()
                .expect("worker header was length-checked"),
        );
        offset += size_of::<u64>();
        value
    };
    let object_count = usize::try_from(next_u64()).map_err(|_| ExtractionError::Backend {
        backend: "pdf",
        reason: "isolated PDF worker object count does not fit this platform".into(),
    })?;
    let page_count = usize::try_from(next_u64()).map_err(|_| ExtractionError::Backend {
        backend: "pdf",
        reason: "isolated PDF worker page count does not fit this platform".into(),
    })?;
    let input_bytes = usize::try_from(next_u64()).map_err(|_| ExtractionError::Backend {
        backend: "pdf",
        reason: "isolated PDF worker input size does not fit this platform".into(),
    })?;
    let text_bytes = usize::try_from(next_u64()).map_err(|_| ExtractionError::Backend {
        backend: "pdf",
        reason: "isolated PDF worker text size does not fit this platform".into(),
    })?;
    if object_count > MAX_PDF_OBJECTS
        || page_count > MAX_PDF_PAGES
        || input_bytes as u64 > MAX_PDF_BYTES
        || text_bytes > MAX_PDF_TEXT_BYTES
        || response.len() != PDF_WORKER_HEADER_BYTES.saturating_add(text_bytes)
    {
        return Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker response violates protocol bounds".into(),
        });
    }
    let text =
        String::from_utf8(response[offset..].to_vec()).map_err(|_| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker returned non-UTF-8 text".into(),
        })?;
    Ok(ParsedPdf {
        text,
        object_count,
        page_count,
        input_bytes,
    })
}

fn safe_worker_diagnostic(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

#[cfg(all(not(test), target_os = "linux"))]
struct PdfWorkerContainmentSetup;

#[cfg(all(not(test), target_os = "linux"))]
impl PdfWorkerContainmentSetup {
    fn configure(command: &mut tokio::process::Command) -> Result<Self, ExtractionError> {
        // Capture the actual spawning process in the parent. This value is
        // moved directly into the post-fork/pre-exec closure; it is never
        // transported through an operator-controlled argument or environment
        // variable.
        // SAFETY: getpid(2) takes no pointers and always returns the caller.
        let expected_parent = unsafe { libc::getpid() };
        command.process_group(0);
        // SAFETY: the callback performs only Linux syscalls and constructs an
        // errno-backed `io::Error`. It runs after fork and before exec.
        unsafe {
            command.pre_exec(move || install_linux_parent_death_signal(expected_parent));
        }
        Ok(Self)
    }

    fn activate(
        self,
        child: &tokio::process::Child,
    ) -> Result<PdfWorkerContainment, ExtractionError> {
        let pid = child.id().ok_or_else(|| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker exited before process-group activation".into(),
        })?;
        let pgid = libc::pid_t::try_from(pid).map_err(|_| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker PID does not fit a POSIX process-group id".into(),
        })?;
        Ok(PdfWorkerContainment { pgid })
    }
}

#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
struct PdfWorkerContainment {
    pgid: libc::pid_t,
}

#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
impl PdfWorkerContainment {
    fn leader_pid(&self) -> libc::pid_t {
        self.pgid
    }

    fn terminate_tree(&self, leader_reaped: bool) -> Result<(), String> {
        if leader_reaped {
            return Err("refusing to signal a numeric PDF process group after leader reap".into());
        }
        // SAFETY: `pgid` is the positive child PID returned after spawning with
        // process_group(0). The unreaped leader still owns that PID, so negating
        // it cannot target a subsequently reused process-group identity.
        if unsafe { libc::kill(-self.pgid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("kill isolated PDF worker process group: {error}"))
        }
    }

    fn process_tree_is_empty_except_leader(&self) -> Result<bool, String> {
        #[cfg(target_os = "linux")]
        {
            linux_pdf_process_group_is_empty_except_leader(self.pgid)
        }
        #[cfg(target_os = "macos")]
        {
            macos_pdf_process_group_is_empty_except_leader(self.pgid)
        }
    }
}

#[cfg(all(not(test), target_os = "linux"))]
fn linux_pdf_process_group_is_empty_except_leader(leader_pid: libc::pid_t) -> Result<bool, String> {
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| format!("enumerate /proc for PDF process-group cleanup: {error}"))?;
    let mut saw_leader = false;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("enumerate PDF process-group member: {error}"))?;
        let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
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
                "inspect /proc/{pid} process group for PDF cleanup: {error}"
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
        return Err("unreaped PDF worker leader was absent from /proc group-empty proof".into());
    }
    Ok(true)
}

#[cfg(all(not(test), target_os = "macos"))]
fn macos_pdf_process_group_is_empty_except_leader(leader_pid: libc::pid_t) -> Result<bool, String> {
    const PID_CAPACITY: usize = 64;
    let mut pids = [0 as libc::pid_t; PID_CAPACITY];
    let buffer_bytes = libc::c_int::try_from(std::mem::size_of_val(&pids))
        .map_err(|_| "macOS PDF process-group buffer does not fit c_int".to_string())?;
    // SAFETY: `pids` is writable storage for `buffer_bytes`. The unreaped
    // waitid identity pins the process-group number for the full query.
    let count = unsafe {
        libc::proc_listpgrppids(
            leader_pid,
            pids.as_mut_ptr().cast::<libc::c_void>(),
            buffer_bytes,
        )
    };
    if count < 0 {
        return Err(format!(
            "enumerate macOS PDF process-group members: {}",
            std::io::Error::last_os_error()
        ));
    }
    let count = usize::try_from(count)
        .map_err(|_| "macOS PDF process-group member count is invalid".to_string())?;
    if count >= pids.len() {
        return Ok(false);
    }
    let members = &pids[..count];
    if !members.contains(&leader_pid) {
        return Err("unreaped PDF worker leader was absent from macOS group-empty proof".into());
    }
    Ok(members.iter().all(|pid| *pid <= 0 || *pid == leader_pid))
}

#[cfg(all(not(test), target_os = "macos"))]
struct PdfWorkerContainmentSetup;

#[cfg(all(not(test), target_os = "macos"))]
impl PdfWorkerContainmentSetup {
    fn configure(command: &mut tokio::process::Command) -> Result<Self, ExtractionError> {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
        Ok(Self)
    }

    fn activate(
        self,
        child: &tokio::process::Child,
    ) -> Result<PdfWorkerContainment, ExtractionError> {
        let pid = child.id().ok_or_else(|| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker exited before process-group activation".into(),
        })?;
        let pgid = libc::pid_t::try_from(pid).map_err(|_| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker PID does not fit a POSIX process-group id".into(),
        })?;
        Ok(PdfWorkerContainment { pgid })
    }
}

/// Arm the Linux kernel's exact parent-death boundary in the post-fork child.
///
/// The immediate `getppid()` comparison closes the documented `prctl` race:
/// if the captured parent died before `PR_SET_PDEATHSIG`, Linux would otherwise
/// never deliver the requested signal. If it dies after `prctl`, the kernel
/// delivers `SIGKILL`.
#[cfg(target_os = "linux")]
fn install_linux_parent_death_signal(expected_parent: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: PR_SET_PDEATHSIG consumes an integer signal number and no
    // pointers. This helper is called only in the post-fork child.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getppid(2) takes no pointers.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

// Unsupported BSD and other Unix targets do not share Linux's
// PR_SET_PDEATHSIG contract and have no native release/CI contract in this
// repository. Keep them explicitly fail-closed rather than silently treating a
// process group alone as parent-death containment.
#[cfg(all(not(test), unix, not(any(target_os = "linux", target_os = "macos"))))]
struct PdfWorkerContainmentSetup;

#[cfg(all(not(test), unix, not(any(target_os = "linux", target_os = "macos"))))]
impl PdfWorkerContainmentSetup {
    fn configure(_command: &mut tokio::process::Command) -> Result<Self, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker parent-liveness containment is unavailable on this Unix platform".into(),
        })
    }

    fn activate(
        self,
        _child: &tokio::process::Child,
    ) -> Result<PdfWorkerContainment, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker parent-liveness containment is unavailable on this Unix platform".into(),
        })
    }
}

#[cfg(all(not(test), unix, not(any(target_os = "linux", target_os = "macos"))))]
struct PdfWorkerContainment;

#[cfg(all(not(test), unix, not(any(target_os = "linux", target_os = "macos"))))]
impl PdfWorkerContainment {
    fn terminate_tree(&self, _leader_reaped: bool) -> Result<(), String> {
        Err(
            "isolated PDF worker parent-liveness containment is unavailable on this Unix platform"
                .into(),
        )
    }

    fn process_tree_is_empty_except_leader(&self) -> Result<bool, String> {
        Err(
            "isolated PDF worker parent-liveness containment is unavailable on this Unix platform"
                .into(),
        )
    }
}

#[cfg(unix)]
fn apply_pdf_worker_resource_limits() -> Result<(), String> {
    macro_rules! lower_limit {
        ($resource:expr, $desired:expr, $label:literal) => {{
            // SAFETY: `current` points to writable storage for getrlimit(2).
            let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
            if unsafe { libc::getrlimit($resource, &raw mut current) } != 0 {
                return Err(format!(
                    "read internal PDF worker {} limit: {}",
                    $label,
                    std::io::Error::last_os_error()
                ));
            }
            let desired = $desired as libc::rlim_t;
            let next = libc::rlimit {
                rlim_cur: current.rlim_cur.min(desired),
                rlim_max: current.rlim_max.min(desired),
            };
            // SAFETY: `next` is fully initialized and never raises either the
            // inherited soft or hard limit.
            if unsafe { libc::setrlimit($resource, &raw const next) } != 0 {
                return Err(format!(
                    "set internal PDF worker {} limit: {}",
                    $label,
                    std::io::Error::last_os_error()
                ));
            }
        }};
    }

    lower_limit!(libc::RLIMIT_CPU, PDF_WORKER_CPU_SECONDS, "CPU");
    lower_limit!(
        libc::RLIMIT_AS,
        PDF_WORKER_MEMORY_BYTES as u64,
        "address-space"
    );
    lower_limit!(libc::RLIMIT_CORE, 0_u64, "core-dump");
    lower_limit!(
        libc::RLIMIT_NOFILE,
        PDF_WORKER_NOFILE_LIMIT,
        "file-descriptor"
    );
    lower_limit!(
        libc::RLIMIT_NPROC,
        PDF_WORKER_PROCESS_LIMIT,
        "process-count"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_pdf_worker_containment() -> Result<(), String> {
    verify_pdf_worker_process_group()?;
    let mut parent_death_signal = 0;
    // SAFETY: PR_GET_PDEATHSIG writes one c_int to the valid pointer supplied.
    if unsafe {
        libc::prctl(
            libc::PR_GET_PDEATHSIG,
            &raw mut parent_death_signal as *mut libc::c_int,
        )
    } != 0
    {
        return Err(format!(
            "inspect internal PDF worker parent-death signal: {}",
            std::io::Error::last_os_error()
        ));
    }
    if parent_death_signal != libc::SIGKILL {
        return Err("internal PDF worker has no authenticated SIGKILL parent-death signal".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_pdf_worker_containment() -> Result<(), String> {
    verify_pdf_worker_process_group()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_pdf_worker_process_group() -> Result<(), String> {
    // SAFETY: getpid(2) and getpgrp(2) take no pointers.
    let pid = unsafe { libc::getpid() };
    let process_group = unsafe { libc::getpgrp() };
    if pid <= 0 || process_group != pid {
        return Err("internal PDF worker is not in its dedicated process group".into());
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn verify_pdf_worker_containment() -> Result<(), String> {
    Err(
        "internal PDF worker parent-liveness containment is unavailable on this Unix platform"
            .into(),
    )
}

#[cfg(all(not(test), windows))]
struct PdfWorkerContainmentSetup {
    job: WindowsPdfJob,
}

#[cfg(all(not(test), windows))]
impl PdfWorkerContainmentSetup {
    fn configure(command: &mut tokio::process::Command) -> Result<Self, ExtractionError> {
        use std::os::windows::process::CommandExt as _;

        let job = WindowsPdfJob::create()?;
        command.env(PDF_WORKER_JOB_ENV, &job.name);
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
        Ok(Self { job })
    }

    fn activate(
        self,
        child: &tokio::process::Child,
    ) -> Result<PdfWorkerContainment, ExtractionError> {
        self.job.assign(child)?;
        Ok(PdfWorkerContainment { job: self.job })
    }
}

#[cfg(all(not(test), windows))]
struct PdfWorkerContainment {
    job: WindowsPdfJob,
}

#[cfg(all(not(test), windows))]
impl PdfWorkerContainment {
    fn terminate_tree(&self, _leader_reaped: bool) -> Result<(), String> {
        self.job.terminate()
    }

    fn process_tree_is_empty_except_leader(&self) -> Result<bool, String> {
        self.job.is_empty()
    }
}

#[cfg(all(not(test), windows))]
struct WindowsPdfJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
    name: String,
}

// SAFETY: a Job Object HANDLE is a process-wide kernel handle. Ownership stays
// unique in `WindowsPdfJob`, and every API used through it is documented as
// callable from arbitrary process threads. The guard is not `Clone` and closes
// the handle exactly once in Drop.
#[cfg(all(not(test), windows))]
unsafe impl Send for WindowsPdfJob {}

#[cfg(all(not(test), windows))]
impl WindowsPdfJob {
    fn create() -> Result<Self, ExtractionError> {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE,
        };
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let name = format!(
            "Local\\NEOTH-PDF-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the UTF-16 name is NUL-terminated and the security attributes
        // pointer is null, requesting the current token's default descriptor.
        let handle: HANDLE = unsafe { CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };
        if handle.is_null() {
            return Err(ExtractionError::Backend {
                backend: "pdf",
                reason: format!(
                    "create isolated PDF worker Job Object: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        // SAFETY: GetLastError reads thread-local Win32 error state immediately
        // after CreateJobObjectW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err(ExtractionError::Backend {
                backend: "pdf",
                reason: "isolated PDF worker Job Object name collision".into(),
            });
        }

        // SAFETY: all-zero is a valid base for this Win32 POD structure.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        info.BasicLimitInformation.PerProcessUserTimeLimit =
            (PDF_WORKER_CPU_SECONDS as i64) * 10_000_000;
        info.ProcessMemoryLimit = PDF_WORKER_MEMORY_BYTES;
        // SAFETY: `handle` is owned and `info` remains live for this call.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(ExtractionError::Backend {
                backend: "pdf",
                reason: format!("configure isolated PDF worker Job Object: {error}"),
            });
        }
        Ok(Self { handle, name })
    }

    fn assign(&self, child: &tokio::process::Child) -> Result<(), ExtractionError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let child_handle = child.raw_handle().ok_or_else(|| ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker exited before Job Object assignment".into(),
        })?;
        // SAFETY: both handles are live for the synchronous assignment call.
        if unsafe { AssignProcessToJobObject(self.handle, child_handle.cast()) } == 0 {
            return Err(ExtractionError::Backend {
                backend: "pdf",
                reason: format!(
                    "assign isolated PDF worker to parent Job Object: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        Ok(())
    }

    fn terminate(&self) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: `handle` remains owned by this guard.
        if unsafe { TerminateJobObject(self.handle, 1) } == 0 {
            return Err(format!(
                "terminate isolated PDF worker Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn is_empty(&self) -> Result<bool, String> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        // SAFETY: all-zero is a valid base for this Win32 POD structure.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` remains owned by this guard, `info` is live writable
        // storage, and the queried class exactly matches its layout.
        if unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!(
                "inspect isolated PDF worker Job Object membership: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(info.ActiveProcesses == 0)
    }
}

#[cfg(all(not(test), windows))]
impl Drop for WindowsPdfJob {
    fn drop(&mut self) {
        // SAFETY: this guard owns the handle and closes it exactly once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
fn apply_pdf_worker_resource_limits() -> Result<(), String> {
    // The parent owns and configures the Job Object. The child deliberately
    // does not create a second job; exact membership is verified only after
    // the parent releases the stdin handshake.
    Ok(())
}

#[cfg(windows)]
fn verify_pdf_worker_containment() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{IsProcessInJob, OpenJobObjectW};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const JOB_OBJECT_QUERY: u32 = 0x0004;
    let name = std::env::var_os(PDF_WORKER_JOB_ENV)
        .ok_or_else(|| "internal PDF worker Job Object name is missing".to_string())?;
    let wide_name: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: the name is NUL-terminated and only query access is requested.
    let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide_name.as_ptr()) };
    if job.is_null() {
        return Err(format!(
            "open parent-owned PDF worker Job Object: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut is_member = 0;
    // SAFETY: both handles are live and `is_member` is writable.
    let checked = unsafe { IsProcessInJob(GetCurrentProcess(), job, &raw mut is_member) };
    // Close the child's query handle immediately. The parent must remain the
    // sole long-lived owner so KILL_ON_JOB_CLOSE works if the daemon dies.
    unsafe { CloseHandle(job) };
    if checked == 0 {
        return Err(format!(
            "verify parent-owned PDF worker Job Object: {}",
            std::io::Error::last_os_error()
        ));
    }
    if is_member == 0 {
        return Err("internal PDF worker is not in the parent-owned Job Object".into());
    }
    Ok(())
}

#[cfg(all(not(test), not(any(unix, windows))))]
struct PdfWorkerContainmentSetup;

#[cfg(all(not(test), not(any(unix, windows))))]
impl PdfWorkerContainmentSetup {
    fn configure(_command: &mut tokio::process::Command) -> Result<Self, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker containment is unavailable on this platform".into(),
        })
    }

    fn activate(
        self,
        _child: &tokio::process::Child,
    ) -> Result<PdfWorkerContainment, ExtractionError> {
        Err(ExtractionError::Backend {
            backend: "pdf",
            reason: "isolated PDF worker containment is unavailable on this platform".into(),
        })
    }
}

#[cfg(all(not(test), not(any(unix, windows))))]
struct PdfWorkerContainment;

#[cfg(all(not(test), not(any(unix, windows))))]
impl PdfWorkerContainment {
    fn terminate_tree(&self, _leader_reaped: bool) -> Result<(), String> {
        Err("isolated PDF worker containment is unavailable on this platform".into())
    }

    fn process_tree_is_empty_except_leader(&self) -> Result<bool, String> {
        Err("isolated PDF worker containment is unavailable on this platform".into())
    }
}

#[cfg(not(any(unix, windows)))]
fn apply_pdf_worker_resource_limits() -> Result<(), String> {
    Err("isolated PDF worker resource limits are unavailable on this platform".into())
}

#[cfg(not(any(unix, windows)))]
fn verify_pdf_worker_containment() -> Result<(), String> {
    Err("isolated PDF worker containment is unavailable on this platform".into())
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl CappedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("PDF extracted-text cap exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Stats {
    chars: usize,
    words: usize,
    lines: usize,
}

fn compute_stats(text: &str) -> Stats {
    Stats {
        chars: text.chars().count(),
        words: text.split_whitespace().count(),
        lines: text.lines().count(),
    }
}

// ── Per-page text extraction ─────────────────────────────────────
//
// The base `PdfExtractor` returns one whitespace-joined text blob;
// for indexer use-cases that want page-anchored recall ("find the
// router decision on page 3 of the proposal"), callers need
// per-page text.

/// One page's extracted text + its 1-indexed page number.
/// `text` may be empty for image-only pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfPage {
    pub page_no: usize,
    pub text: String,
}

/// Split a `pdf-extract` whole-document text blob into per-page
/// entries. The library emits a form-feed character (`\x0C`) on
/// page boundaries — we use that as the splitter. Pages without
/// a form-feed (single-page PDFs) return one entry with the full
/// text. Pages with no text after the split are kept as empty
/// entries so page numbering stays stable for recall anchoring.
pub fn split_into_pages(whole_text: &str) -> Vec<PdfPage> {
    if whole_text.is_empty() {
        return Vec::new();
    }
    whole_text
        .split('\x0c')
        .enumerate()
        .map(|(idx, page_text)| PdfPage {
            page_no: idx + 1,
            text: page_text.to_string(),
        })
        .collect()
}

/// Extract per-page text from a PDF asset. Uses the same isolated extraction
/// boundary as [`PdfExtractor`] so callers indexing for page-anchored
/// recall ("which page mentions the router config?") consume the
/// shape directly.
pub async fn extract_pages(asset: &Asset) -> Result<Vec<PdfPage>, ExtractionError> {
    if asset.kind() != AssetKind::Pdf {
        return Err(ExtractionError::Unsupported {
            backend: "pdf",
            got: asset.kind(),
        });
    }
    let extraction = extract_pdf_asset(asset).await?;
    Ok(split_into_pages(&extraction.text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    const PDF_PDEATH_TEST_ROLE: &str = "NEOTH_TEST_PDF_PDEATH_ROLE";

    #[cfg(target_os = "linux")]
    const PDF_PDEATH_TEST_NAME: &str =
        "media::pdf::tests::linux_parent_death_signal_kills_child_after_parent_exit";

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_parent_death_setup_rejects_a_mismatched_captured_parent() {
        use std::os::unix::process::CommandExt as _;

        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.arg("--help").process_group(0);
        // SAFETY: this is the same syscall-only pre-exec helper used by the
        // production worker spawn. The deliberately impossible parent PID
        // exercises the race-closing comparison before exec.
        unsafe {
            command.pre_exec(|| install_linux_parent_death_signal(-1));
        }
        let error = match command.spawn() {
            Err(error) => error,
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("mismatched captured parent must reject the child before exec");
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_parent_death_signal_kills_child_after_parent_exit() {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;

        match std::env::var(PDF_PDEATH_TEST_ROLE).as_deref() {
            Ok("child") => {
                std::thread::sleep(std::time::Duration::from_secs(30));
                panic!("parent-death child survived after its spawning parent exited");
            }
            Ok("parent") => {
                // SAFETY: getpid(2) takes no pointers and captures the exact
                // process that is about to spawn the child.
                let expected_parent = unsafe { libc::getpid() };
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", PDF_PDEATH_TEST_NAME, "--nocapture"])
                    .env(PDF_PDEATH_TEST_ROLE, "child")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .process_group(0);
                // SAFETY: production and regression use the same syscall-only
                // post-fork helper and captured parent identity.
                unsafe {
                    command.pre_exec(move || install_linux_parent_death_signal(expected_parent));
                }
                // The fixture must exit this parent immediately so Linux can
                // deliver PDEATHSIG to the child. Waiting here would invalidate
                // the contract under test; PID 1 reaps the orphan after exit.
                #[allow(clippy::zombie_processes)]
                let child = command.spawn().expect("spawn parent-death child fixture");
                println!("PDF_PDEATH_CHILD_PID={}", child.id());
                std::io::stdout()
                    .flush()
                    .expect("flush parent-death child PID");
                return;
            }
            Ok(other) => panic!("unexpected parent-death test role: {other}"),
            Err(_) => {}
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PDF_PDEATH_TEST_NAME, "--nocapture"])
            .env(PDF_PDEATH_TEST_ROLE, "parent")
            .output()
            .expect("spawn parent-death parent fixture");
        assert!(
            output.status.success(),
            "parent fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("parent fixture stdout is UTF-8");
        let child_pid = stdout
            .lines()
            .find_map(|line| {
                line.split_once("PDF_PDEATH_CHILD_PID=")
                    .map(|(_, pid)| pid.trim())
            })
            .expect("parent fixture reported child PID")
            .parse::<libc::pid_t>()
            .expect("child PID is numeric");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while linux_process_exists(child_pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if linux_process_exists(child_pid) {
            // SAFETY: the fixture was started as process-group leader. Cleanup
            // prevents a failed regression from leaking its sleeping child.
            unsafe {
                libc::kill(-child_pid, libc::SIGKILL);
            }
            panic!("parent-death child {child_pid} remained alive after its parent exited");
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_process_exists(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 performs an existence/permission probe only.
        if unsafe { libc::kill(pid, 0) } == 0 {
            // Minimal containers do not always reap orphaned children
            // promptly. A zombie has already released its address space and
            // cannot perform work, so treat it as terminated for this
            // parent-death regression instead of waiting on PID 1.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
            return !stat
                .as_deref()
                .and_then(|value| value.rsplit_once(") ").map(|(_, tail)| tail))
                .is_some_and(|tail| tail.starts_with('Z') || tail.starts_with('X'));
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[test]
    fn compute_stats_counts_basic_text() {
        let s = compute_stats("hello world\nsecond line");
        assert_eq!(s.lines, 2);
        assert_eq!(s.words, 4);
        assert!(s.chars > 0);
    }

    #[test]
    fn compute_stats_handles_empty_text() {
        let s = compute_stats("");
        assert_eq!(s.lines, 0);
        assert_eq!(s.words, 0);
        assert_eq!(s.chars, 0);
    }

    #[test]
    fn capped_writer_accepts_exact_limit_and_rejects_next_byte() {
        let mut writer = CappedWriter::new(4);
        writer.write_all(b"four").expect("exact cap");
        let error = writer.write_all(b"!").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(writer.exceeded);
        assert_eq!(writer.bytes, b"four");
    }

    #[test]
    fn pdf_input_ceiling_is_fail_closed() {
        assert!(enforce_pdf_byte_ceiling(MAX_PDF_BYTES).is_ok());
        let error = enforce_pdf_byte_ceiling(MAX_PDF_BYTES + 1).unwrap_err();
        assert!(
            matches!(error, ExtractionError::Backend { backend: "pdf", .. }),
            "{error:?}"
        );
    }

    #[test]
    fn isolated_worker_protocol_round_trips_exactly() {
        let expected = ParsedPdf {
            text: "page one\u{c}page two".into(),
            object_count: 17,
            page_count: 2,
            input_bytes: 4096,
        };
        let encoded = encode_worker_response(&expected).expect("encode bounded worker response");
        assert!(encoded.len() <= PDF_WORKER_STDOUT_CAP_BYTES);
        let decoded = decode_worker_response(&encoded).expect("decode worker response");
        assert_eq!(decoded.text, expected.text);
        assert_eq!(decoded.object_count, expected.object_count);
        assert_eq!(decoded.page_count, expected.page_count);
        assert_eq!(decoded.input_bytes, expected.input_bytes);
    }

    #[test]
    fn isolated_worker_protocol_rejects_trailing_or_oversized_claims() {
        let parsed = ParsedPdf {
            text: "bounded".into(),
            object_count: 1,
            page_count: 1,
            input_bytes: 32,
        };
        let mut trailing = encode_worker_response(&parsed).expect("encode");
        trailing.push(0);
        assert!(decode_worker_response(&trailing).is_err());

        let mut oversized = encode_worker_response(&parsed).expect("encode");
        let text_len_offset = PDF_WORKER_MAGIC.len() + 3 * size_of::<u64>();
        oversized[text_len_offset..text_len_offset + size_of::<u64>()]
            .copy_from_slice(&((MAX_PDF_TEXT_BYTES as u64) + 1).to_be_bytes());
        assert!(decode_worker_response(&oversized).is_err());
    }

    #[tokio::test]
    async fn bounded_worker_pipe_enforces_exact_cap() {
        use tokio::io::AsyncWriteExt as _;

        let (mut exact_writer, exact_reader) = tokio::io::duplex(32);
        let exact = tokio::spawn(async move {
            exact_writer.write_all(b"four").await.unwrap();
            exact_writer.shutdown().await.unwrap();
        });
        assert_eq!(
            read_bounded_worker_pipe(exact_reader, 4).await.unwrap(),
            b"four"
        );
        exact.await.unwrap();

        let (mut oversized_writer, oversized_reader) = tokio::io::duplex(32);
        let oversized = tokio::spawn(async move {
            oversized_writer.write_all(b"five!").await.unwrap();
            oversized_writer.shutdown().await.unwrap();
        });
        assert!(matches!(
            read_bounded_worker_pipe(oversized_reader, 4).await,
            Err(PdfWorkerPipeError::LimitExceeded)
        ));
        oversized.await.unwrap();
    }

    #[test]
    fn worker_path_preflight_is_bounded_before_process_work() {
        let path = PathBuf::from("a".repeat(MAX_PDF_PATH_BYTES + 1));
        let asset = Asset::Path {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            path,
        };
        assert!(matches!(
            preflight_pdf_asset(&asset),
            Err(ExtractionError::Backend { backend: "pdf", .. })
        ));
    }

    #[tokio::test]
    async fn extract_returns_unsupported_for_non_pdf() {
        let extractor = PdfExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: vec![0x89, b'P', b'N', b'G'],
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported { backend: "pdf", .. }
        ));
    }

    /// Garbage bytes claiming to be a PDF must surface as a `Backend`
    /// error from the underlying parser, never panic.
    #[tokio::test]
    async fn extract_errors_cleanly_on_garbage_pdf_bytes() {
        let extractor = PdfExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"not actually a pdf".to_vec(),
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(
            matches!(err, ExtractionError::Backend { backend: "pdf", .. }),
            "got: {err:?}",
        );
    }

    // ── M-1 scaffolding tests ─────────────────────────────────────

    #[test]
    fn split_into_pages_empty_text_returns_empty() {
        assert!(split_into_pages("").is_empty());
    }

    #[test]
    fn split_into_pages_no_form_feed_returns_single_page() {
        let pages = split_into_pages("just one page of text");
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].page_no, 1);
        assert_eq!(pages[0].text, "just one page of text");
    }

    #[test]
    fn split_into_pages_form_feed_splits_correctly() {
        // 3 pages separated by form-feed chars (the exact splitter
        // `pdf-extract` emits between pages).
        let body = "page one\x0cpage two body\x0cpage three";
        let pages = split_into_pages(body);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].page_no, 1);
        assert_eq!(pages[0].text, "page one");
        assert_eq!(pages[1].page_no, 2);
        assert_eq!(pages[1].text, "page two body");
        assert_eq!(pages[2].page_no, 3);
        assert_eq!(pages[2].text, "page three");
    }

    #[test]
    fn split_into_pages_preserves_empty_pages_for_stable_numbering() {
        // Image-only middle page emits an empty entry between two
        // text pages. Caller MUST see page_no = 2 for the empty
        // slot so per-page recall anchors stay correct.
        let body = "page one\x0c\x0cpage three";
        let pages = split_into_pages(body);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[1].page_no, 2);
        assert!(
            pages[1].text.is_empty(),
            "empty middle page must stay an empty entry, not be dropped"
        );
        assert_eq!(pages[2].page_no, 3);
    }

    #[test]
    fn pdf_page_struct_round_trip() {
        let p = PdfPage {
            page_no: 7,
            text: "body".into(),
        };
        assert_eq!(p.page_no, 7);
        assert_eq!(p.text, "body");
    }
}
