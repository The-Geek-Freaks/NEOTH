//! Contained execution of the external Graphify Python distribution.
//!
//! A mapped corpus is untrusted input.  In particular, its working directory
//! must never select the Python interpreter/module and an interrupted Tokio
//! future must not leave a Graphify child (or its descendants) behind.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{io::AsyncReadExt as _, process::Command, sync::Mutex};

// Process groups do not provide containment on Unix: a descendant can create
// a new session with `setsid(2)` and escape a later group kill. This runner
// therefore supports execution only where it can establish a Windows Job
// Object before the child begins running. Refuse compilation elsewhere rather
// than silently weakening that contract on an unfamiliar platform.
#[cfg(not(any(unix, windows)))]
compile_error!("Graphify runner requires an explicitly supported containment platform");

const RUNTIME_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
const RUNTIME_VERIFY_OUTPUT_CAP: usize = 8 * 1024;
const PROCESS_DIAGNOSTIC_CAP_CHARS: usize = 512;
const PROCESS_DIAGNOSTIC_TRUNCATION_MARKER: char = '…';

/// Maximum execution time and captured output for a single Graphify action.
#[derive(Clone, Debug)]
pub struct GraphifyRunLimits {
    label: String,
    timeout: Duration,
    stdout_cap_bytes: usize,
    stderr_cap_bytes: usize,
}

impl GraphifyRunLimits {
    pub fn new(
        label: impl Into<String>,
        timeout: Duration,
        stdout_cap_bytes: usize,
        stderr_cap_bytes: usize,
    ) -> Result<Self> {
        let label = label.into();
        if label.trim().is_empty() {
            bail!("Graphify runner label must not be empty");
        }
        if timeout.is_zero() {
            bail!("Graphify runner timeout for {label} must be non-zero");
        }
        if stdout_cap_bytes == 0 || stderr_cap_bytes == 0 {
            bail!("Graphify runner output caps for {label} must be non-zero");
        }
        Ok(Self {
            label,
            timeout,
            stdout_cap_bytes,
            stderr_cap_bytes,
        })
    }
}

/// Deliberately narrow environment passed to a Graphify subprocess.
///
/// The child starts with no inherited environment. Only OS bootstrap, locale,
/// temporary-directory, and certificate-discovery variables are copied from
/// the daemon; the Python bootstrap variables are never admitted.
#[derive(Clone, Debug, Default)]
pub struct GraphifyEnvironment {
    overrides: BTreeMap<OsString, OsString>,
}

impl GraphifyEnvironment {
    pub fn runtime() -> Self {
        Self::default()
    }

    /// Grant the credentialless Graphify label child access to exactly one
    /// ephemeral loopback broker and one already-authorized model. No generic
    /// environment authority (loader paths, proxies, keys, or shell hooks) is
    /// representable through this API.
    pub fn label_broker(base_url: &str, model: &str) -> Result<Self> {
        let parsed =
            url::Url::parse(base_url.trim()).context("parse Graphify label broker base URL")?;
        if parsed.scheme() != "http"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.port().is_none()
            || parsed.host_str() != Some("127.0.0.1")
            || !is_valid_broker_capability_path(parsed.path())
        {
            bail!(
                "Graphify label broker must be an explicit http://127.0.0.1:<port>/graphify-<uuid>/v1 URL"
            );
        }
        let model = model.trim();
        if model.is_empty()
            || model.len() > 256
            || !model.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
            })
        {
            bail!("Graphify label broker model must be a non-empty safe model identifier");
        }

        let mut overrides = BTreeMap::new();
        overrides.insert(OsString::from("OLLAMA_BASE_URL"), parsed.to_string().into());
        overrides.insert(OsString::from("OLLAMA_MODEL"), OsString::from(model));
        Ok(Self { overrides })
    }

    fn apply(&self, command: &mut Command) {
        command.env_clear();
        for name in INHERITED_RUNTIME_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, value) in &self.overrides {
            command.env(name, value);
        }
    }
}

fn is_valid_broker_capability_path(path: &str) -> bool {
    let Some(capability) = path
        .strip_prefix("/graphify-")
        .and_then(|path| path.strip_suffix("/v1"))
    else {
        return false;
    };
    let Ok(capability) = uuid::Uuid::parse_str(capability) else {
        return false;
    };
    !capability.is_nil() && matches!(capability.get_version_num(), 4 | 7)
}

// These are deliberately boring process-bootstrap values. In particular, do
// not inherit shell startup, loader, language-package, proxy, or credential
// variables from the daemon. Graphify gets network authority only through an
// explicit broker capability supplied by its caller.
const INHERITED_RUNTIME_ENV: &[&str] = &[
    "PATH",
    "SystemRoot",
    "WINDIR",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "TMP",
    "TEMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
];

/// A verified, canonical absolute Python executable.  The path is private so
/// callers cannot turn a previously verified token into a mutable command.
#[derive(Clone, Debug)]
pub struct GraphifyRuntime(Arc<VerifiedRuntime>);

#[derive(Debug)]
struct VerifiedRuntime {
    executable: PathBuf,
    identity: ExecutableIdentity,
}

impl GraphifyRuntime {
    /// Resolve and verify an interpreter once. Repeated calls reuse the
    /// verified opaque runtime token for the canonical executable.
    pub async fn discover(requested: impl AsRef<OsStr>) -> Result<Self> {
        ensure_graphify_containment_supported()?;
        let executable = resolve_python_executable(requested.as_ref())?;
        let identity = ExecutableIdentity::capture(&executable)?;
        {
            let mut cache = runtime_cache().lock().await;
            if let Some(runtime) = cache.get(&executable) {
                if runtime.identity == identity {
                    return Ok(Self(Arc::clone(runtime)));
                }
                // An executable replacement must never inherit prior trust.
                cache.remove(&executable);
            }
        }

        let limits = GraphifyRunLimits::new(
            "graphify-runtime-verification",
            RUNTIME_VERIFY_TIMEOUT,
            RUNTIME_VERIFY_OUTPUT_CAP,
            RUNTIME_VERIFY_OUTPUT_CAP,
        )?;
        let output = run_contained_process(
            &executable,
            ["-I", "-m", "graphify", "--version"],
            None,
            &GraphifyEnvironment::runtime(),
            &limits,
        )
        .await
        .with_context(|| format!("verify Graphify runtime {}", executable.display()))?;
        require_successful_process(&limits, output)?;

        let verified_identity = ExecutableIdentity::capture(&executable)?;
        if verified_identity != identity {
            bail!(
                "Graphify Python executable changed while it was being verified: {}",
                executable.display()
            );
        }

        let runtime = Arc::new(VerifiedRuntime {
            executable,
            identity: verified_identity,
        });
        // Do not retain the cache mutex while the verification subprocess is
        // alive. A concurrent probe may duplicate this bounded verification,
        // but it cannot cause an unverified token to be returned.
        let mut cache = runtime_cache().lock().await;
        if let Some(existing) = cache.get(&runtime.executable)
            && existing.identity == runtime.identity
        {
            return Ok(Self(Arc::clone(existing)));
        }
        cache.insert(runtime.executable.clone(), Arc::clone(&runtime));
        Ok(Self(runtime))
    }

    fn revalidate(&self) -> Result<()> {
        let current = ExecutableIdentity::capture(&self.0.executable)?;
        if current != self.0.identity {
            bail!(
                "refusing to execute changed Graphify Python runtime: {}",
                self.0.executable.display()
            );
        }
        Ok(())
    }
}

fn runtime_cache() -> &'static Mutex<BTreeMap<PathBuf, Arc<VerifiedRuntime>>> {
    static CACHE: OnceLock<Mutex<BTreeMap<PathBuf, Arc<VerifiedRuntime>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Stable identity of an executable at the point where it was verified.
/// Canonical path alone is not an identity: an attacker with write access to
/// the interpreter location could atomically replace the file after a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableIdentity {
    canonical_path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    size: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
    #[cfg(windows)]
    file_size: u64,
    #[cfg(windows)]
    last_write_time: u64,
}

impl ExecutableIdentity {
    fn capture(executable: &Path) -> Result<Self> {
        let canonical_path = std::fs::canonicalize(executable).with_context(|| {
            format!(
                "canonicalize Graphify Python executable {}",
                executable.display()
            )
        })?;
        if canonical_path != executable {
            bail!(
                "Graphify Python executable path changed after runtime selection: {}",
                executable.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::metadata(&canonical_path).with_context(|| {
                format!(
                    "read Graphify Python executable metadata {}",
                    canonical_path.display()
                )
            })?;
            Ok(Self {
                canonical_path,
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.size(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
            })
        }
        #[cfg(windows)]
        {
            capture_windows_executable_identity(canonical_path)
        }
    }
}

#[cfg(windows)]
fn capture_windows_executable_identity(canonical_path: PathBuf) -> Result<ExecutableIdentity> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = std::fs::File::open(&canonical_path).with_context(|| {
        format!(
            "open Graphify Python executable {}",
            canonical_path.display()
        )
    })?;
    // SAFETY: `BY_HANDLE_FILE_INFORMATION` is a C POD output structure for
    // this API, so an all-zero initial value is valid before Windows fills it.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` remains open for this call; its raw handle has the ABI
    // representation expected by Windows, and `information` is writable for
    // the full duration of the call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        bail!(
            "read Graphify Python executable identity {}: {}",
            canonical_path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(ExecutableIdentity {
        canonical_path,
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        file_size: (u64::from(information.nFileSizeHigh) << 32)
            | u64::from(information.nFileSizeLow),
        last_write_time: (u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime),
    })
}

/// A single Graphify command. `new("python", …)` is retained for existing
/// call sites; the runner resolves that selector to an absolute, verified
/// runtime before it ever changes into a corpus directory.
#[derive(Clone, Debug)]
pub struct GraphifyRunRequest {
    requested_runtime: OsString,
    runtime: Option<GraphifyRuntime>,
    limits: GraphifyRunLimits,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
    environment: GraphifyEnvironment,
}

impl GraphifyRunRequest {
    pub fn new(requested_runtime: impl AsRef<OsStr>, limits: GraphifyRunLimits) -> Self {
        Self {
            requested_runtime: requested_runtime.as_ref().to_os_string(),
            runtime: None,
            limits,
            args: Vec::new(),
            current_dir: None,
            environment: GraphifyEnvironment::runtime(),
        }
    }

    pub fn with_runtime(runtime: GraphifyRuntime, limits: GraphifyRunLimits) -> Self {
        Self {
            requested_runtime: runtime.0.executable.as_os_str().to_os_string(),
            runtime: Some(runtime),
            limits,
            args: Vec::new(),
            current_dir: None,
            environment: GraphifyEnvironment::runtime(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        self
    }

    pub fn current_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.current_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn environment(mut self, environment: GraphifyEnvironment) -> Self {
        self.environment = environment;
        self
    }
}

/// Run a Graphify operation under a verified interpreter and Windows Job
/// Object containment. This accepts only `-I -m graphify …` invocations.
pub async fn run_graphify_process(request: GraphifyRunRequest) -> Result<std::process::Output> {
    if !is_graphify_module_invocation(&request.args) {
        bail!(
            "{} must invoke the isolated Graphify module as `-I -m graphify …`",
            request.limits.label
        );
    }
    ensure_graphify_containment_supported()?;
    let runtime = match request.runtime {
        Some(runtime) => runtime,
        None => GraphifyRuntime::discover(&request.requested_runtime).await?,
    };
    runtime.revalidate()?;
    let output = run_contained_process(
        &runtime.0.executable,
        request.args,
        request.current_dir.as_deref(),
        &request.environment,
        &request.limits,
    )
    .await?;
    require_successful_process(&request.limits, output)
}

fn is_graphify_module_invocation(args: &[OsString]) -> bool {
    args.first().is_some_and(|arg| arg == "-I")
        && args.get(1).is_some_and(|arg| arg == "-m")
        && args.get(2).is_some_and(|arg| arg == "graphify")
}

fn resolve_python_executable(requested: &OsStr) -> Result<PathBuf> {
    let path = Path::new(requested);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if requested == OsStr::new("python") || requested == OsStr::new("python3") {
        find_python_on_path(requested)?
    } else {
        bail!(
            "Graphify runtime must be the opaque `python` selector or an absolute Python executable, got {:?}",
            requested
        );
    };
    let canonical = std::fs::canonicalize(&candidate).with_context(|| {
        format!(
            "canonicalize Graphify Python executable {}",
            candidate.display()
        )
    })?;
    if !canonical.is_absolute() || !canonical.is_file() {
        bail!(
            "Graphify runtime is not an absolute executable file: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn find_python_on_path(name: &OsStr) -> Result<PathBuf> {
    let path =
        std::env::var_os("PATH").context("PATH is unavailable while locating Graphify Python")?;
    #[cfg(windows)]
    let names = [name.to_os_string(), OsString::from("python.exe")];
    #[cfg(not(windows))]
    let names = [name.to_os_string()];

    for directory in std::env::split_paths(&path) {
        // An empty PATH component means the current directory on POSIX (and
        // has platform-dependent semantics on Windows). Never let a corpus
        // working directory supply the interpreter.
        if directory.as_os_str().is_empty() {
            continue;
        }
        for name in &names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("could not locate {:?} on PATH for Graphify", name)
}

async fn run_contained_process<I, S>(
    executable: &Path,
    args: I,
    current_dir: Option<&Path>,
    environment: &GraphifyEnvironment,
    limits: &GraphifyRunLimits,
) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    environment.apply(&mut command);
    configure_containment(&mut command)?;

    let child = command
        .spawn()
        .with_context(|| format!("spawn {}", limits.label))?;
    let mut child = ContainedChild::activate(child)
        .with_context(|| format!("activate {} process containment", limits.label))?;
    let stdout = match child.child_mut().stdout.take() {
        Some(stdout) => stdout,
        None => {
            child.terminate_and_reap().await;
            bail!("Graphify child stdout pipe was not created");
        }
    };
    let stderr = match child.child_mut().stderr.take() {
        Some(stderr) => stderr,
        None => {
            child.terminate_and_reap().await;
            bail!("Graphify child stderr pipe was not created");
        }
    };

    let run = async {
        tokio::try_join!(
            async { child.child_mut().wait().await.map_err(anyhow::Error::from) },
            read_capped(stdout, limits.stdout_cap_bytes, "stdout"),
            read_capped(stderr, limits.stderr_cap_bytes, "stderr"),
        )
    };
    match tokio::time::timeout(limits.timeout, run).await {
        Ok(Ok((status, stdout, stderr))) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => {
            child.terminate_and_reap().await;
            Err(error).with_context(|| format!("{} output collection failed", limits.label))
        }
        Err(_) => {
            child.terminate_and_reap().await;
            bail!(
                "{} exceeded its {:?} execution deadline",
                limits.label,
                limits.timeout
            );
        }
    }
}

async fn read_capped<R>(mut reader: R, cap: usize, stream: &'static str) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(cap.min(8 * 1024));
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > cap {
            bail!("Graphify {stream} exceeded its {cap}-byte output cap");
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn bounded_diagnostic(stderr: &[u8], stdout: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let decoded = String::from_utf8_lossy(bytes);
    let sanitized = crate::security::redact::sanitize_tool_output(decoded.trim());
    let diagnostic = sanitized.trim();
    if diagnostic.is_empty() {
        return "no stderr or stdout diagnostic".to_owned();
    }

    let mut chars = diagnostic.chars();
    let mut bounded: String = chars.by_ref().take(PROCESS_DIAGNOSTIC_CAP_CHARS).collect();
    if chars.next().is_some() {
        // Reserve one character inside the cap for the truncation marker.
        // `pop` and `push` operate on Unicode scalar values, so a multibyte
        // diagnostic can never be cut at an invalid UTF-8 boundary.
        let _ = bounded.pop();
        bounded.push(PROCESS_DIAGNOSTIC_TRUNCATION_MARKER);
    }
    bounded
}

fn require_successful_process(
    limits: &GraphifyRunLimits,
    output: std::process::Output,
) -> Result<std::process::Output> {
    if output.status.success() {
        return Ok(output);
    }

    let status = match output.status.code() {
        Some(code) => format!("exit code {code}"),
        None => format!("termination status {}", output.status),
    };
    bail!(
        "{} failed with {status}: {}",
        limits.label,
        bounded_diagnostic(&output.stderr, &output.stdout)
    );
}

/// Verifies the non-negotiable process-containment prerequisite shared by
/// every Graphify execution path.
///
/// This deliberately performs no runtime/module subprocess probe. Consumers
/// such as `neoth doctor` can call it first to distinguish an unavailable
/// platform from a Python/module repairable runtime failure without claiming
/// that package importability implies executable readiness.
pub(crate) fn ensure_graphify_containment_supported() -> Result<()> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(unix)]
    {
        bail!(
            "Graphify runner is unavailable on Unix: process groups cannot contain descendants that escape with setsid(2); Windows Job Object containment is required"
        );
    }
}

fn configure_containment(command: &mut Command) -> Result<()> {
    ensure_graphify_containment_supported()?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command
            .as_std_mut()
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    let _ = command;
    Ok(())
}

struct ContainedChild {
    child: Option<tokio::process::Child>,
    #[cfg(windows)]
    job: WindowsChildJob,
}

impl ContainedChild {
    fn activate(child: tokio::process::Child) -> Result<Self> {
        #[cfg(windows)]
        {
            let job = WindowsChildJob::create()?;
            if let Err(error) = job.assign(&child).and_then(|()| job.resume(&child)) {
                drop(job);
                return Err(error);
            }
            Ok(Self {
                child: Some(child),
                job,
            })
        }
        #[cfg(unix)]
        {
            let _ = child;
            bail!("Graphify containment activation is unavailable on Unix")
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("contained Graphify child is present until reaped")
    }

    async fn terminate_and_reap(&mut self) {
        self.terminate_now();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait().await;
        }
    }

    fn terminate_now(&mut self) {
        #[cfg(windows)]
        self.job.terminate();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        // Futures may be cancelled at any await point. The Windows Job guard
        // makes that cancellation fail closed for the whole job. A Tokio task
        // cannot await from Drop, so hand the direct child to a detached reaper
        // whenever a runtime is still alive.
        self.terminate_now();
        if let Some(mut child) = self.child.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

#[cfg(windows)]
struct WindowsChildJob(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: a Windows Job Object handle is a process-wide kernel handle, not a
// thread-affine pointer. This wrapper owns the handle exclusively and only
// moves that ownership between Tokio worker threads; all operations are Win32
// handle operations and `Drop` closes it exactly once.
#[cfg(windows)]
unsafe impl Send for WindowsChildJob {}

#[cfg(windows)]
impl WindowsChildJob {
    fn create() -> Result<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: null security attributes and name request a new unnamed Job
        // Object using Windows defaults; no raw pointer outlives this call.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            bail!(
                "create Graphify Windows Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: this Win32 POD structure permits zero initialization; only
        // the documented `LimitFlags` member is required for this operation.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `handle` is an owned live Job Object; the raw pointer is
        // derived from `info`, which stays initialized and alive through this
        // call, and the exact structure size is supplied to Win32.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `handle` was returned as a non-null owned Job Object
            // handle and has not been closed on this failure path.
            unsafe { CloseHandle(handle) };
            return Err(error).context("configure Graphify Windows Job Object");
        }
        Ok(Self(handle))
    }

    fn assign(&self, child: &tokio::process::Child) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        let process = child
            .raw_handle()
            .context("Graphify exited before Job Object assignment")?;
        // SAFETY: `self.0` is this wrapper's live Job Object handle and the
        // child retains ownership of its live process handle during the call.
        if unsafe { AssignProcessToJobObject(self.0, process.cast()) } == 0 {
            bail!(
                "assign Graphify to Windows Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    fn resume(&self, child: &tokio::process::Child) -> Result<()> {
        // SAFETY: this declaration matches the documented ntdll ABI for
        // `NtResumeProcess`; the call below passes a live process handle.
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtResumeProcess(process_handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
        }
        let process = child
            .raw_handle()
            .context("Graphify exited before suspended-process resume")?;
        // SAFETY: `process` is borrowed from the live suspended child and its
        // cast preserves the HANDLE representation required by ntdll.
        let status = unsafe { NtResumeProcess(process.cast()) };
        if status < 0 {
            self.terminate();
            bail!("resume Graphify after Job Object assignment: NTSTATUS {status:#x}");
        }
        Ok(())
    }

    fn terminate(&self) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: `self.0` remains an owned live Job Object handle for this
        // call. Windows accepts the non-zero termination exit code.
        unsafe {
            let _ = TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsChildJob {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE covers cancellation/unwind and any descendant
        // that the direct child created before the timeout path runs.
        // SAFETY: this wrapper exclusively owns `self.0`; this Drop is its
        // only close path after successful construction.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_broker_exposes_only_its_two_allowlisted_values() {
        let environment = GraphifyEnvironment::label_broker(
            "http://127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
            "qwen2.5-coder:7b",
        )
        .unwrap();
        assert_eq!(environment.overrides.len(), 2);
        assert_eq!(
            environment.overrides.get(OsStr::new("OLLAMA_BASE_URL")),
            Some(&OsString::from(
                "http://127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1"
            ))
        );
        for forbidden in [
            "PYTHONPATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "HTTP_PROXY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
        ] {
            assert!(
                !environment.overrides.contains_key(OsStr::new(forbidden)),
                "{forbidden} must never be representable in a Graphify child environment"
            );
        }
    }

    #[test]
    fn label_broker_rejects_non_loopback_malformed_and_unsafe_capabilities() {
        for url in [
            "https://127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
            "http://localhost:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
            "http://[::1]:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
            "http://127.0.0.1:39123/v1",
            "http://127.0.0.1:39123/graphify-not-a-uuid/v1",
            "http://user:password@127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
            "http://127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1?proxy=http://evil",
        ] {
            assert!(
                GraphifyEnvironment::label_broker(url, "qwen2.5-coder:7b").is_err(),
                "{url} must not be accepted as a broker capability"
            );
        }
        assert!(
            GraphifyEnvironment::label_broker(
                "http://127.0.0.1:39123/graphify-018f5b56-69e0-7b11-9caa-023eeb607485/v1",
                "model with whitespace"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_non_python_runtime_selector() {
        let error = resolve_python_executable(OsStr::new("python; malicious"))
            .expect_err("runtime selector must not be a shell fragment");
        assert!(error.to_string().contains("opaque `python` selector"));
    }

    #[test]
    fn accepts_only_isolated_graphify_module_invocation() {
        assert!(is_graphify_module_invocation(&[
            OsString::from("-I"),
            OsString::from("-m"),
            OsString::from("graphify"),
            OsString::from("update"),
        ]));
        assert!(!is_graphify_module_invocation(&[
            OsString::from("-m"),
            OsString::from("graphify"),
        ]));
        assert!(!is_graphify_module_invocation(&[
            OsString::from("-I"),
            OsString::from("-m"),
            OsString::from("graphifyy"),
        ]));
    }

    #[test]
    fn executable_identity_rejects_replacement_after_verification() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let canonical = std::fs::canonicalize(file.path()).unwrap();
        std::fs::write(&canonical, b"verified-runtime").unwrap();
        let before = ExecutableIdentity::capture(&canonical).unwrap();
        std::fs::write(&canonical, b"replaced-runtime-with-different-size").unwrap();
        let after = ExecutableIdentity::capture(&canonical).unwrap();
        assert_ne!(
            before, after,
            "runtime replacement must invalidate its token"
        );
    }

    #[test]
    fn nonzero_process_failure_has_a_bounded_status_and_diagnostic() {
        let limits =
            GraphifyRunLimits::new("central-nonzero-test", Duration::from_secs(1), 4096, 4096)
                .unwrap();
        let oversized_diagnostic = "🦀".repeat(PROCESS_DIAGNOSTIC_CAP_CHARS * 4);
        let error = require_successful_process(
            &limits,
            std::process::Output {
                status: failed_exit_status(),
                stdout: Vec::new(),
                stderr: oversized_diagnostic.into_bytes(),
            },
        )
        .expect_err("non-zero child status must fail the Graphify operation")
        .to_string();

        let diagnostic = error
            .strip_prefix("central-nonzero-test failed with exit code 23: ")
            .expect("the bounded diagnostic follows the preserved process status");
        assert_eq!(
            diagnostic.chars().count(),
            PROCESS_DIAGNOSTIC_CAP_CHARS,
            "the truncation marker must fit inside the diagnostic cap"
        );
        assert_eq!(
            diagnostic
                .chars()
                .filter(|character| *character == '🦀')
                .count(),
            PROCESS_DIAGNOSTIC_CAP_CHARS - 1,
            "Unicode diagnostics must truncate only at character boundaries"
        );
        assert_eq!(
            diagnostic.chars().last(),
            Some(PROCESS_DIAGNOSTIC_TRUNCATION_MARKER)
        );
    }

    #[test]
    fn nonzero_process_diagnostic_sanitizes_terminal_controls_and_secrets() {
        let secret = "mysupersecretvalue123";
        let untrusted = format!(
            "API_KEY={secret} \x1b[31mfailed\x1b[0m \x1b]8;;https://attacker.invalid\x07linked\x1b]8;;\x07 before\rafter\x08"
        );
        let diagnostic = bounded_diagnostic(untrusted.as_bytes(), &[]);

        assert!(
            diagnostic.chars().count() <= PROCESS_DIAGNOSTIC_CAP_CHARS,
            "sanitized diagnostics remain inside the central cap"
        );
        assert!(!diagnostic.contains(secret));
        assert!(diagnostic.contains("REDACTED"));
        assert!(!diagnostic.contains('\x1b'));
        assert!(!diagnostic.contains('\r'));
        assert!(
            !diagnostic.chars().any(char::is_control),
            "terminal controls must not survive into error chains"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_graphify_execution_fails_closed_before_runtime_resolution() {
        let limits =
            GraphifyRunLimits::new("unix-containment-test", Duration::from_secs(1), 64, 64)
                .unwrap();
        let error = run_graphify_process(
            GraphifyRunRequest::new("python", limits).args(["-I", "-m", "graphify"]),
        )
        .await
        .expect_err("Unix process groups are not safe Graphify containment")
        .to_string();
        assert!(error.contains("unavailable on Unix"));
        assert!(error.contains("setsid(2)"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn public_runner_converts_a_nonzero_child_status_into_an_error() {
        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let runtime = GraphifyRuntime(Arc::new(VerifiedRuntime {
            identity: ExecutableIdentity::capture(&executable).unwrap(),
            executable,
        }));
        let limits =
            GraphifyRunLimits::new("public-nonzero-test", Duration::from_secs(5), 4096, 4096)
                .unwrap();
        // The Rust test executable rejects this Python-only argument sequence.
        // It is nevertheless structurally valid for the public Graphify API,
        // so this exercises the central non-zero-status handling after the Job
        // Object has activated.
        let error = run_graphify_process(
            GraphifyRunRequest::with_runtime(runtime, limits).args(["-I", "-m", "graphify"]),
        )
        .await
        .expect_err("the public runner must reject a non-zero child status")
        .to_string();
        assert!(error.contains("public-nonzero-test failed with exit code"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_environment_removes_inherited_python_injection_variables() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let _environment = crate::test_env::lock();
        // Declared after the lock so panic cleanup restores every variable
        // before another environment-mutating test may acquire that lock.
        let restore_environment = EnvironmentRestoreGuard {
            python_path: std::env::var_os("PYTHONPATH"),
            python_home: std::env::var_os("PYTHONHOME"),
            virtual_env: std::env::var_os("VIRTUAL_ENV"),
            hostile_inherit: std::env::var_os("GRAPHIFY_TEST_HOSTILE_INHERIT"),
        };
        unsafe {
            std::env::set_var("PYTHONPATH", "attacker-path");
            std::env::set_var("PYTHONHOME", "attacker-home");
            std::env::set_var("VIRTUAL_ENV", "attacker-venv");
            std::env::set_var("GRAPHIFY_TEST_HOSTILE_INHERIT", "must-not-leak");
        }
        let mut command = Command::new("/usr/bin/env");
        GraphifyEnvironment::runtime().apply(&mut command);
        // The process-global environment must remain serialized until the
        // child has inherited it. Blocking on a test-owned runtime retains
        // that invariant without a direct await under the std mutex guard.
        // Command::output consults Tokio's process reactor eagerly, so build
        // it only after block_on has entered the test-owned runtime.
        let output = runtime.block_on(async move {
            let mut command = command;
            command.output().await
        });
        drop(restore_environment);
        let output = output.unwrap();
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(!environment.contains("PYTHONPATH="));
        assert!(!environment.contains("PYTHONHOME="));
        assert!(!environment.contains("VIRTUAL_ENV="));
        assert!(!environment.contains("GRAPHIFY_TEST_HOSTILE_INHERIT="));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_timeout_kills_parent_and_grandchild_job_tree() {
        let (_directory, powershell, script, marker) = windows_parent_and_grandchild_fixture();
        let limits = GraphifyRunLimits::new(
            "windows-tree-timeout-test",
            Duration::from_millis(250),
            4096,
            4096,
        )
        .unwrap();
        let args = windows_script_args(&script);
        let result = run_contained_process(
            &powershell,
            args.iter().map(OsString::as_os_str),
            None,
            &GraphifyEnvironment::runtime(),
            &limits,
        )
        .await;
        assert!(result.is_err());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !marker.exists(),
            "grandchild survived Windows Job Object timeout"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_abort_kills_parent_and_grandchild_job_tree() {
        let (_directory, powershell, script, marker) = windows_parent_and_grandchild_fixture();
        let args = windows_script_args(&script);
        let limits = GraphifyRunLimits::new(
            "windows-tree-abort-test",
            Duration::from_secs(30),
            4096,
            4096,
        )
        .unwrap();
        let task = tokio::spawn(async move {
            run_contained_process(
                &powershell,
                args.iter().map(OsString::as_os_str),
                None,
                &GraphifyEnvironment::runtime(),
                &limits,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !marker.exists(),
            "grandchild survived Windows Job Object abort"
        );
    }

    #[cfg(unix)]
    struct EnvironmentRestoreGuard {
        python_path: Option<OsString>,
        python_home: Option<OsString>,
        virtual_env: Option<OsString>,
        hostile_inherit: Option<OsString>,
    }

    #[cfg(unix)]
    impl Drop for EnvironmentRestoreGuard {
        fn drop(&mut self) {
            restore_environment_variable("PYTHONPATH", self.python_path.take());
            restore_environment_variable("PYTHONHOME", self.python_home.take());
            restore_environment_variable("VIRTUAL_ENV", self.virtual_env.take());
            restore_environment_variable(
                "GRAPHIFY_TEST_HOSTILE_INHERIT",
                self.hostile_inherit.take(),
            );
        }
    }

    #[cfg(unix)]
    fn restore_environment_variable(name: &str, value: Option<OsString>) {
        unsafe {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }

    #[cfg(unix)]
    fn failed_exit_status() -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        std::process::ExitStatus::from_raw(23 << 8)
    }

    #[cfg(windows)]
    fn failed_exit_status() -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        std::process::ExitStatus::from_raw(23)
    }

    #[cfg(windows)]
    fn windows_parent_and_grandchild_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("job-tree.ps1");
        let marker = directory.path().join("grandchild-survived.txt");
        // `Start-Process` creates a direct descendant after the suspended
        // parent has been assigned to the Job Object. Breakaway is not enabled
        // on that job, so the cmd grandchild must inherit the same job.
        let contents = format!(
            "$child = 'timeout /t 1 /nobreak > nul & echo orphan > \"{}\"'\r\nStart-Process -WindowStyle Hidden -FilePath $env:ComSpec -ArgumentList @('/d', '/c', $child)\r\nStart-Sleep -Seconds 30\r\n",
            marker.display(),
        );
        std::fs::write(&script, contents).unwrap();
        let system_root = std::env::var_os("SystemRoot").expect("Windows SystemRoot is set");
        (
            directory,
            PathBuf::from(system_root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe"),
            script,
            marker,
        )
    }

    #[cfg(windows)]
    fn windows_script_args(script: &Path) -> Vec<OsString> {
        vec![
            OsString::from("-NoLogo"),
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-ExecutionPolicy"),
            OsString::from("Bypass"),
            OsString::from("-File"),
            script.as_os_str().to_os_string(),
        ]
    }
}
