//! Bounded ownership for short, trusted GUI CLI probes.
//!
//! This is deliberately **not** the chat process-tree supervisor. Chat owns
//! request secrets and, on Linux, an isolation namespace. A dashboard probe
//! owns only a locally resolved, fixed-argv CLI invocation. It still needs a
//! real owner: a direct-child kill followed by a reader `join` is not safe
//! when a descendant inherited stdout or stderr.
//!
//! The module has no networking surface. Callers retain binary/argv authority;
//! this module receives an already-built [`std::process::Command`].

use std::io::{Read as _, Write as _};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(20);
const INTERNAL_GUARDIAN_ARG: &str = "--neoth-internal-trusted-probe-guardian-v1";
const GUARDIAN_REQUEST_MAGIC: [u8; 4] = *b"NPG1";
const GUARDIAN_RESPONSE_MAGIC: [u8; 4] = *b"NPG2";
const MAX_GUARDIAN_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const USAGE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const USAGE_PROBE_STDOUT_BYTES: usize = 1024 * 1024;
pub(crate) const USAGE_PROBE_STDERR_BYTES: usize = 16 * 1024;
pub(crate) const USAGE_PROBE_DRAIN_GRACE: Duration = Duration::from_millis(250);
const MAX_GUARDIAN_RESPONSE_BYTES: usize = USAGE_PROBE_STDOUT_BYTES + USAGE_PROBE_STDERR_BYTES + 16;

/// Fixed resource policy for a single trusted CLI probe.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbePolicy {
    /// End-to-end wall-clock budget, measured before spawning the child.
    pub timeout: Duration,
    /// Retained stdout prefix. The reader continues draining after this cap.
    pub stdout_cap_bytes: usize,
    /// Retained stderr prefix. The reader continues draining after this cap.
    pub stderr_cap_bytes: usize,
    /// Maximum post-termination time spent waiting for reader handoff.
    pub drain_grace: Duration,
}

pub(crate) const fn fixed_usage_probe_policy() -> ProbePolicy {
    ProbePolicy {
        timeout: USAGE_PROBE_TIMEOUT,
        stdout_cap_bytes: USAGE_PROBE_STDOUT_BYTES,
        stderr_cap_bytes: USAGE_PROBE_STDERR_BYTES,
        drain_grace: USAGE_PROBE_DRAIN_GRACE,
    }
}

/// A completed, bounded capture. Diagnostics are intentionally returned as
/// bytes; rendering and redaction remain the caller's responsibility.
#[derive(Debug)]
pub(crate) struct ProbeOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Stable failure classes for GUI copy. Never include child-controlled output
/// here: the usage panel must not render tool output as a diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeError {
    Cancelled,
    TimedOut,
    OutputTooLarge { stream: &'static str },
    SpawnFailed,
    ContainmentUnavailable,
    PipeUnavailable { stream: &'static str },
    ReaderUnavailable { stream: &'static str },
    ReaderFailed { stream: &'static str },
    WaitFailed,
    NonZeroExit,
}

impl ProbeError {
    /// Static, non-sensitive text suitable for the D2 unavailable state.
    pub(crate) const fn as_static_message(self) -> &'static str {
        match self {
            Self::Cancelled => "usage probe cancelled",
            Self::TimedOut => "usage probe timed out",
            Self::OutputTooLarge { .. } => "usage probe output exceeded limit",
            Self::SpawnFailed => "usage probe could not start",
            Self::ContainmentUnavailable => "usage probe could not start safely",
            Self::PipeUnavailable { stream: "stdout" } => "usage probe stdout unavailable",
            Self::PipeUnavailable { stream: "stderr" } => "usage probe stderr unavailable",
            Self::PipeUnavailable { .. } => "usage probe pipe unavailable",
            Self::ReaderUnavailable { stream: "stdout" } => "usage probe stdout reader unavailable",
            Self::ReaderUnavailable { stream: "stderr" } => "usage probe stderr reader unavailable",
            Self::ReaderUnavailable { .. } => "usage probe reader unavailable",
            Self::ReaderFailed { stream: "stdout" } => "usage probe stdout read failed",
            Self::ReaderFailed { stream: "stderr" } => "usage probe stderr read failed",
            Self::ReaderFailed { .. } => "usage probe read failed",
            Self::WaitFailed => "usage probe wait failed",
            Self::NonZeroExit => "usage probe failed",
        }
    }
}

/// Cancellation owned by the GUI worker lifecycle, not by the probe child.
///
/// The caller must retain one handle for as long as it may cancel a running
/// probe. Calling [`Self::cancel`] transfers child cleanup to the supervisor's
/// terminal owner; it never exposes a raw child handle to UI code.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProbeCancellation {
    cancelled: Arc<AtomicBool>,
}

/// Consume the fixed internal guardian mode before normal GUI initialisation.
///
/// `main` must call this before Slint/window setup and exit when it returns
/// `Ok(true)`. The mode accepts exactly one private binary request frame on
/// stdin; it never parses shell text or arbitrary CLI argv.
pub(crate) fn run_internal_guardian_if_requested() -> Result<bool, ProbeError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(mode) = arguments.next() else {
        return Ok(false);
    };
    if mode != std::ffi::OsStr::new(INTERNAL_GUARDIAN_ARG) {
        return Ok(false);
    }
    if arguments.next().is_some() {
        return Err(ProbeError::ContainmentUnavailable);
    }
    run_internal_guardian()?;
    Ok(true)
}

/// A deliberately tiny binary request: the GUI parent serialises only the
/// already-resolved executable and its fixed dashboard JSON argv. The guardian checks
/// that argv again before spawning, so helper-mode invocation cannot turn into
/// a generic command runner.
struct GuardianRequest {
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    timeout: Duration,
    stdout_cap_bytes: usize,
    stderr_cap_bytes: usize,
}

#[cfg(unix)]
fn run_internal_guardian() -> Result<(), ProbeError> {
    let mut control = std::io::stdin();
    let request = read_guardian_request(&mut control)?;
    if !is_fixed_probe_argv(&request.args) {
        return Err(ProbeError::ContainmentUnavailable);
    }
    use std::os::unix::ffi::OsStringExt as _;
    let program = std::ffi::OsString::from_vec(request.program);
    if !guardian_program_is_trusted(&program) {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let mut command = Command::new(program);
    // The guardian is a fresh GUI child and would otherwise inherit ambient
    // one-shot launcher capabilities which `spawn_neothd_plain` removed from
    // the original command. Keep this deny-list at the guardian authority
    // boundary as well as in main's command builder.
    scrub_probe_environment(&mut command);
    command.args(request.args.into_iter().map(std::ffi::OsString::from_vec));
    // The GUI parent retains the write end after sending the request. EOF is
    // therefore both explicit outer cancellation and parent-liveness proof:
    // if the GUI dies, its pipe handle closes and this guardian kills/reaps the
    // trusted target process group before returning.
    let cancellation = ProbeCancellation::new();
    let control_cancellation = cancellation.clone();
    let _control_watcher = thread::Builder::new()
        .name("neoth-probe-guardian-control".into())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = control.read(&mut byte);
            control_cancellation.cancel();
        })
        .map_err(|_| ProbeError::ReaderUnavailable { stream: "stdin" })?;
    let output = run_direct(
        &mut command,
        ProbePolicy {
            timeout: request.timeout,
            stdout_cap_bytes: request.stdout_cap_bytes,
            stderr_cap_bytes: request.stderr_cap_bytes,
            drain_grace: USAGE_PROBE_DRAIN_GRACE,
        },
        &cancellation,
        None,
    );
    write_guardian_response(std::io::stdout(), output)
}

#[cfg(not(unix))]
fn run_internal_guardian() -> Result<(), ProbeError> {
    Err(ProbeError::ContainmentUnavailable)
}

fn is_fixed_probe_argv(args: &[Vec<u8>]) -> bool {
    let as_text: Option<Vec<&str>> = args
        .iter()
        .map(|arg| std::str::from_utf8(arg).ok())
        .collect();
    let Some(args) = as_text else {
        return false;
    };
    match args.as_slice() {
        ["meter", "--format", "json"] => true,
        ["cost", "top-sessions", "--output", "json"] => true,
        ["usage", "--format", "json", "--days", "1"] => true,
        [
            "usage",
            "--since-unix",
            since,
            "--until-unix",
            until,
            "--format",
            "json",
        ] => {
            !since.is_empty()
                && !until.is_empty()
                && since.bytes().all(|byte| byte.is_ascii_digit())
                && until.bytes().all(|byte| byte.is_ascii_digit())
                && since
                    .parse::<u64>()
                    .ok()
                    .zip(until.parse::<u64>().ok())
                    .is_some_and(|(since, until)| since <= until)
        }
        _ => false,
    }
}

fn is_fixed_probe_command(command: &Command) -> bool {
    let args: Vec<&std::ffi::OsStr> = command.get_args().collect();
    let decimal = |value: &std::ffi::OsStr| {
        value.to_str().and_then(|value| {
            (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| value.parse::<u64>().ok())
                .flatten()
        })
    };
    match args.as_slice() {
        [meter, format, json] => {
            *meter == std::ffi::OsStr::new("meter")
                && *format == std::ffi::OsStr::new("--format")
                && *json == std::ffi::OsStr::new("json")
        }
        [cost, top_sessions, output, json] => {
            *cost == std::ffi::OsStr::new("cost")
                && *top_sessions == std::ffi::OsStr::new("top-sessions")
                && *output == std::ffi::OsStr::new("--output")
                && *json == std::ffi::OsStr::new("json")
        }
        [usage, format, json, days, one] => {
            *usage == std::ffi::OsStr::new("usage")
                && *format == std::ffi::OsStr::new("--format")
                && *json == std::ffi::OsStr::new("json")
                && *days == std::ffi::OsStr::new("--days")
                && *one == std::ffi::OsStr::new("1")
        }
        [usage, since_flag, since, until_flag, until, format, json] => {
            *usage == std::ffi::OsStr::new("usage")
                && *since_flag == std::ffi::OsStr::new("--since-unix")
                && decimal(since).is_some()
                && *until_flag == std::ffi::OsStr::new("--until-unix")
                && decimal(until).is_some()
                && decimal(since)
                    .zip(decimal(until))
                    .is_some_and(|(since, until)| since <= until)
                && *format == std::ffi::OsStr::new("--format")
                && *json == std::ffi::OsStr::new("json")
        }
        _ => false,
    }
}

fn policy_is_fixed_usage(policy: ProbePolicy) -> bool {
    policy.timeout == USAGE_PROBE_TIMEOUT
        && policy.stdout_cap_bytes == USAGE_PROBE_STDOUT_BYTES
        && policy.stderr_cap_bytes == USAGE_PROBE_STDERR_BYTES
        && policy.drain_grace == USAGE_PROBE_DRAIN_GRACE
}

fn scrub_probe_environment(command: &mut Command) {
    for variable in [
        "NEOTH_GUI_READY_FILE",
        "NEOTH_GUI_READY_TOKEN",
        "NEOTH_GUI_PARENT_COMMIT",
        "NEOTH_PRODUCT_LAUNCHER",
        "NEOTH_READY_FILE",
        "NEOTH_READY_TOKEN",
        "NEOTH_INTERFACE",
    ] {
        command.env_remove(variable);
    }
    command
        .env("NO_COLOR", "1")
        .env("RUST_LOG_STYLE", "never")
        .env("CLICOLOR", "0")
        .env("NEOTH_LOG", "error");
}

fn read_guardian_request(mut input: impl std::io::Read) -> Result<GuardianRequest, ProbeError> {
    let mut consumed = 0_usize;
    let mut magic = [0_u8; 4];
    read_frame_exact(&mut input, &mut magic, &mut consumed)?;
    if magic != GUARDIAN_REQUEST_MAGIC {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let timeout_ms = read_frame_u64(&mut input, &mut consumed)?;
    let stdout_cap_bytes = usize::try_from(read_frame_u32(&mut input, &mut consumed)?)
        .map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stderr_cap_bytes = usize::try_from(read_frame_u32(&mut input, &mut consumed)?)
        .map_err(|_| ProbeError::ContainmentUnavailable)?;
    let program_len = usize::from(read_frame_u16(&mut input, &mut consumed)?);
    let mut args_len = [0_u8; 1];
    read_frame_exact(&mut input, &mut args_len, &mut consumed)?;
    let args_len = usize::from(args_len[0]);
    if program_len == 0
        || !matches!(args_len, 3 | 4 | 5 | 7)
        || !consumed
            .checked_add(program_len)
            .is_some_and(|used| used <= MAX_GUARDIAN_REQUEST_BYTES)
    {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let mut program = vec![0_u8; program_len];
    read_frame_exact(&mut input, &mut program, &mut consumed)?;
    let mut args = Vec::with_capacity(args_len);
    for _ in 0..args_len {
        let len = usize::from(read_frame_u16(&mut input, &mut consumed)?);
        if !consumed
            .checked_add(len)
            .is_some_and(|used| used <= MAX_GUARDIAN_REQUEST_BYTES)
        {
            return Err(ProbeError::ContainmentUnavailable);
        }
        let mut argument = vec![0_u8; len];
        read_frame_exact(&mut input, &mut argument, &mut consumed)?;
        args.push(argument);
    }
    let timeout = Duration::from_millis(timeout_ms);
    if timeout_ms == 0
        || timeout != USAGE_PROBE_TIMEOUT
        || stdout_cap_bytes != USAGE_PROBE_STDOUT_BYTES
        || stderr_cap_bytes != USAGE_PROBE_STDERR_BYTES
        || args_len == 0
    {
        return Err(ProbeError::ContainmentUnavailable);
    }
    Ok(GuardianRequest {
        program,
        args,
        timeout,
        stdout_cap_bytes,
        stderr_cap_bytes,
    })
}

pub(crate) fn canonical_trusted_sibling(
    directory: &std::path::Path,
    name: &str,
) -> Option<std::path::PathBuf> {
    let directory = std::fs::canonicalize(directory).ok()?;
    let candidate = std::fs::canonicalize(directory.join(name)).ok()?;
    (candidate.is_file()
        && candidate.parent() == Some(directory.as_path())
        && candidate.file_name() == Some(std::ffi::OsStr::new(name)))
    .then_some(candidate)
}

fn guardian_program_is_trusted(program: &std::ffi::OsStr) -> bool {
    let Ok(actual) = std::fs::canonicalize(std::path::Path::new(program)) else {
        return false;
    };
    if !actual.is_file() {
        return false;
    }
    let Ok(guardian_path) = std::env::current_exe() else {
        return false;
    };
    let Ok(guardian) = std::fs::canonicalize(guardian_path) else {
        return false;
    };
    let Some(directory) = guardian.parent() else {
        return false;
    };
    // Match the launcher's public-first compatibility contract, but only for
    // canonical siblings of this exact GUI executable. PATH-selected
    // lookalikes are never trusted for the privileged bounded-probe path.
    let names = if cfg!(windows) {
        ["neoth.exe", "neothd.exe"]
    } else {
        ["neoth", "neothd"]
    };
    names.into_iter().any(|name| {
        canonical_trusted_sibling(directory, name).is_some_and(|expected| actual == expected)
    })
}

fn read_frame_exact(
    input: &mut impl std::io::Read,
    bytes: &mut [u8],
    consumed: &mut usize,
) -> Result<(), ProbeError> {
    *consumed = consumed
        .checked_add(bytes.len())
        .filter(|used| *used <= MAX_GUARDIAN_REQUEST_BYTES)
        .ok_or(ProbeError::ContainmentUnavailable)?;
    input
        .read_exact(bytes)
        .map_err(|_| ProbeError::ReaderFailed { stream: "stdin" })
}

fn read_frame_u16(input: &mut impl std::io::Read, consumed: &mut usize) -> Result<u16, ProbeError> {
    let mut bytes = [0_u8; 2];
    read_frame_exact(input, &mut bytes, consumed)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_frame_u32(input: &mut impl std::io::Read, consumed: &mut usize) -> Result<u32, ProbeError> {
    let mut bytes = [0_u8; 4];
    read_frame_exact(input, &mut bytes, consumed)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_frame_u64(input: &mut impl std::io::Read, consumed: &mut usize) -> Result<u64, ProbeError> {
    let mut bytes = [0_u8; 8];
    read_frame_exact(input, &mut bytes, consumed)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_guardian_response(
    mut output: impl std::io::Write,
    result: Result<ProbeOutput, ProbeError>,
) -> Result<(), ProbeError> {
    let (code, stdout, stderr) = match result {
        Ok(output) if output.status.success() => (0_i32, output.stdout, output.stderr),
        Ok(_) => (1_i32, Vec::new(), Vec::new()),
        Err(_) => (-1_i32, Vec::new(), Vec::new()),
    };
    let stdout_len = u32::try_from(stdout.len()).map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stderr_len = u32::try_from(stderr.len()).map_err(|_| ProbeError::ContainmentUnavailable)?;
    let code_bytes = code.to_le_bytes();
    let stdout_len_bytes = stdout_len.to_le_bytes();
    let stderr_len_bytes = stderr_len.to_le_bytes();
    for bytes in [
        GUARDIAN_RESPONSE_MAGIC.as_slice(),
        code_bytes.as_slice(),
        stdout_len_bytes.as_slice(),
        stderr_len_bytes.as_slice(),
        stdout.as_slice(),
        stderr.as_slice(),
    ] {
        output
            .write_all(bytes)
            .map_err(|_| ProbeError::ReaderFailed { stream: "stdout" })?;
    }
    output
        .flush()
        .map_err(|_| ProbeError::ReaderFailed { stream: "stdout" })
}

impl ProbeCancellation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct CappedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

/// Keep a bounded prefix but always drain to EOF. Stopping at the cap would
/// let a full pipe block the child before containment can terminate it.
fn drain_capped(
    mut reader: impl std::io::Read,
    cap: usize,
    exceeded_stream: u8,
    exceeded: Arc<AtomicU8>,
) -> std::io::Result<CappedRead> {
    let mut bytes = Vec::with_capacity(cap.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut was_exceeded = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(CappedRead {
                bytes,
                exceeded: was_exceeded,
            });
        }
        let remaining = cap.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        if retained != read {
            was_exceeded = true;
            // Publish as soon as the cap is crossed, rather than waiting for
            // EOF. A noisy child can otherwise keep draining forever.
            let _ =
                exceeded.compare_exchange(0, exceeded_stream, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

type ReaderResult = std::io::Result<CappedRead>;

struct OwnedProbe {
    child: Child,
    containment: PlatformContainment,
    stdout_rx: mpsc::Receiver<ReaderResult>,
    stderr_rx: mpsc::Receiver<ReaderResult>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    direct_status: Option<ExitStatus>,
    exceeded: Arc<AtomicU8>,
    control: Option<ChildStdin>,
}

impl OwnedProbe {
    fn spawn(
        command: &mut Command,
        policy: ProbePolicy,
        control_frame: Option<&[u8]>,
    ) -> Result<Self, ProbeError> {
        command
            .stdin(if control_frame.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let setup = PlatformContainmentSetup::configure(command)?;
        let mut child = command.spawn().map_err(|_| ProbeError::SpawnFailed)?;
        let containment = match setup.activate(&child) {
            Ok(containment) => containment,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let control = if let Some(frame) = control_frame {
            let mut stdin = match child.stdin.take() {
                Some(stdin) => stdin,
                None => {
                    let owned = Self::without_readers(child, containment);
                    owned.transfer_to_reaper();
                    return Err(ProbeError::PipeUnavailable { stream: "stdin" });
                }
            };
            if stdin.write_all(frame).is_err() || stdin.flush().is_err() {
                let owned = Self::without_readers(child, containment);
                owned.transfer_to_reaper();
                return Err(ProbeError::ReaderFailed { stream: "stdin" });
            }
            Some(stdin)
        } else {
            None
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let owned = Self::without_readers(child, containment);
                owned.transfer_to_reaper();
                return Err(ProbeError::PipeUnavailable { stream: "stdout" });
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                let owned = Self::without_readers(child, containment);
                owned.transfer_to_reaper();
                return Err(ProbeError::PipeUnavailable { stream: "stderr" });
            }
        };

        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        let exceeded = Arc::new(AtomicU8::new(0));
        let stdout_exceeded = Arc::clone(&exceeded);
        let stdout_reader = match thread::Builder::new()
            .name("neoth-probe-stdout".into())
            .spawn(move || {
                let _ = stdout_tx.send(drain_capped(
                    stdout,
                    policy.stdout_cap_bytes,
                    1,
                    stdout_exceeded,
                ));
            }) {
            Ok(reader) => reader,
            Err(_) => {
                let owned = Self::without_readers(child, containment);
                owned.transfer_to_reaper();
                return Err(ProbeError::ReaderUnavailable { stream: "stdout" });
            }
        };
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        let stderr_exceeded = Arc::clone(&exceeded);
        let stderr_reader = match thread::Builder::new()
            .name("neoth-probe-stderr".into())
            .spawn(move || {
                let _ = stderr_tx.send(drain_capped(
                    stderr,
                    policy.stderr_cap_bytes,
                    2,
                    stderr_exceeded,
                ));
            }) {
            Ok(reader) => reader,
            Err(_) => {
                // The stdout handle is deliberately detached. It can be blocked
                // in a pipe held by a descendant; cleanup must not join it here.
                let owned = Self {
                    child,
                    containment,
                    stdout_rx,
                    stderr_rx,
                    stdout_reader: Some(stdout_reader),
                    stderr_reader: None,
                    direct_status: None,
                    exceeded,
                    control,
                };
                owned.transfer_to_reaper();
                return Err(ProbeError::ReaderUnavailable { stream: "stderr" });
            }
        };

        Ok(Self {
            child,
            containment,
            stdout_rx,
            stderr_rx,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            direct_status: None,
            exceeded,
            control,
        })
    }

    fn without_readers(child: Child, containment: PlatformContainment) -> Self {
        let (_stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        let (_stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        Self {
            child,
            containment,
            stdout_rx,
            stderr_rx,
            stdout_reader: None,
            stderr_reader: None,
            direct_status: None,
            exceeded: Arc::new(AtomicU8::new(0)),
            control: None,
        }
    }

    fn poll_direct(&mut self) -> Result<Option<ExitStatus>, ProbeError> {
        if self.direct_status.is_none() {
            self.direct_status = self.child.try_wait().map_err(|_| ProbeError::WaitFailed)?;
        }
        Ok(self.direct_status)
    }

    fn output_cap_error(&self) -> Option<ProbeError> {
        match self.exceeded.load(Ordering::Acquire) {
            1 => Some(ProbeError::OutputTooLarge { stream: "stdout" }),
            2 => Some(ProbeError::OutputTooLarge { stream: "stderr" }),
            _ => None,
        }
    }

    fn terminate_boundary(&mut self) {
        // Terminate the platform-owned tree *before* collecting reader output.
        // A direct leader can already have exited while a descendant still owns
        // stdout/stderr, so `child.kill()` alone is never sufficient.
        if self.control.take().is_some() {
            // Guardian observes EOF and terminates/reaps its own target group.
            // Give it the bounded caller grace before a reaper force-kills the
            // guardian itself on a later retry.
            return;
        }
        self.containment.terminate();
        let _ = self.child.kill();
    }

    fn collect_or_transfer(
        mut self,
        terminal_error: Option<ProbeError>,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProbeError> {
        self.terminate_boundary();

        let Some(reap_deadline) = Instant::now().checked_add(policy.drain_grace) else {
            self.transfer_to_reaper();
            return Err(terminal_error.unwrap_or(ProbeError::WaitFailed));
        };
        loop {
            match self.poll_direct() {
                Ok(Some(_)) if self.containment.is_empty() => break,
                Ok(_) if Instant::now() < reap_deadline => thread::sleep(REAP_POLL_INTERVAL),
                Ok(_) | Err(_) => {
                    self.transfer_to_reaper();
                    return Err(terminal_error.unwrap_or(ProbeError::WaitFailed));
                }
            }
        }

        // The shared deadline prevents two serial recv_timeout calls from
        // stretching the terminal path to 2x drain_grace.
        let Some(readers_deadline) = Instant::now().checked_add(policy.drain_grace) else {
            self.transfer_to_reaper();
            return Err(terminal_error.unwrap_or(ProbeError::ReaderFailed { stream: "stdout" }));
        };
        let stdout = match recv_before(&self.stdout_rx, readers_deadline) {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.transfer_to_reaper();
                return Err(terminal_error.unwrap_or(ProbeError::ReaderFailed { stream: "stdout" }));
            }
            Err(()) => {
                self.transfer_to_reaper();
                return Err(terminal_error.unwrap_or(ProbeError::ReaderFailed { stream: "stdout" }));
            }
        };
        let stderr = match recv_before(&self.stderr_rx, readers_deadline) {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.transfer_to_reaper();
                return Err(terminal_error.unwrap_or(ProbeError::ReaderFailed { stream: "stderr" }));
            }
            Err(()) => {
                self.transfer_to_reaper();
                return Err(terminal_error.unwrap_or(ProbeError::ReaderFailed { stream: "stderr" }));
            }
        };

        // Reader completion is observed through its channel before joining. A
        // join here is therefore non-blocking apart from a panic unwind.
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
        if stdout.exceeded {
            return Err(ProbeError::OutputTooLarge { stream: "stdout" });
        }
        if stderr.exceeded {
            return Err(ProbeError::OutputTooLarge { stream: "stderr" });
        }
        if let Some(error) = terminal_error {
            return Err(error);
        }
        let Some(status) = self.direct_status else {
            return Err(ProbeError::WaitFailed);
        };
        if !status.success() {
            return Err(ProbeError::NonZeroExit);
        }
        Ok(ProbeOutput {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }

    /// Transfer every OS and reader owner into a terminal reaper. This is the
    /// cancellation/error boundary: callers must never drop an owned probe and
    /// then attempt to join a reader themselves.
    fn transfer_to_reaper(mut self) {
        self.terminate_boundary();
        // Keep the sole owner in an Arc until thread creation succeeds. Unlike
        // `spawn(move || self...)`, this lets the rare creation failure reap
        // the direct child synchronously instead of losing it to Child::drop.
        let pending = Arc::new(Mutex::new(Some(self)));
        let reaper_pending = Arc::clone(&pending);
        let fallback = thread::Builder::new()
            .name("neoth-probe-reaper".into())
            .spawn(move || {
                let owned = reaper_pending.lock().ok().and_then(|mut slot| slot.take());
                if let Some(owned) = owned {
                    owned.reap_in_background();
                }
            });
        if fallback.is_err() {
            // A thread-start failure is exceptional. The containment object is
            // still dropped only after a termination request; on Windows that
            // closes the kill-on-close Job, and Unix sends the process-group
            // termination signal. Reap the direct child synchronously so this
            // exceptional path cannot accumulate zombies; reader handles are
            // intentionally detached because they may still await inherited
            // descriptors from a descendant.
            if let Ok(mut slot) = pending.lock() {
                if let Some(mut owned) = slot.take() {
                    let _ = owned.child.wait();
                }
            }
        }
    }

    fn reap_in_background(mut self) {
        loop {
            self.terminate_boundary();
            match self.poll_direct() {
                Ok(Some(_)) if self.containment.is_empty() => break,
                _ => thread::sleep(REAP_POLL_INTERVAL),
            }
        }
        // Do not block the terminal reaper on a pipe whose writer escaped a
        // best-effort Unix process group. The JoinHandle destructor detaches.
        let _ = self.stdout_rx.try_recv();
        let _ = self.stderr_rx.try_recv();
    }
}

fn recv_before<T>(receiver: &mpsc::Receiver<T>, deadline: Instant) -> Result<T, ()> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| ())
}

/// Run a trusted, fixed-argv CLI command under bounded capture and owned
/// cleanup. The deadline is absolute: it is calculated before setup/spawn.
fn run_direct(
    command: &mut Command,
    policy: ProbePolicy,
    cancellation: &ProbeCancellation,
    control_frame: Option<&[u8]>,
) -> Result<ProbeOutput, ProbeError> {
    let deadline = Instant::now()
        .checked_add(policy.timeout)
        .ok_or(ProbeError::ContainmentUnavailable)?;
    if cancellation.is_cancelled() {
        return Err(ProbeError::Cancelled);
    }
    let mut probe = OwnedProbe::spawn(command, policy, control_frame)?;
    loop {
        if let Some(error) = probe.output_cap_error() {
            return probe.collect_or_transfer(Some(error), policy);
        }
        if cancellation.is_cancelled() {
            return probe.collect_or_transfer(Some(ProbeError::Cancelled), policy);
        }
        if Instant::now() >= deadline {
            return probe.collect_or_transfer(Some(ProbeError::TimedOut), policy);
        }
        match probe.poll_direct() {
            Ok(Some(_)) => return probe.collect_or_transfer(None, policy),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => return probe.collect_or_transfer(Some(error), policy),
        }
    }
}

/// Run through the private guardian on Unix so a parent/control EOF owns the
/// target PGID lifetime. Windows already has kernel-enforced Job containment.
pub(crate) fn run(
    command: &mut Command,
    policy: ProbePolicy,
    cancellation: &ProbeCancellation,
) -> Result<ProbeOutput, ProbeError> {
    if !is_fixed_probe_command(command)
        || !guardian_program_is_trusted(command.get_program())
        || !policy_is_fixed_usage(policy)
    {
        return Err(ProbeError::ContainmentUnavailable);
    }
    #[cfg(unix)]
    {
        return run_via_guardian(command, policy, cancellation);
    }
    #[cfg(not(unix))]
    {
        run_direct(command, policy, cancellation, None)
    }
}

#[cfg(unix)]
fn run_via_guardian(
    command: &mut Command,
    policy: ProbePolicy,
    cancellation: &ProbeCancellation,
) -> Result<ProbeOutput, ProbeError> {
    let frame = encode_guardian_request(command, policy)?;
    let executable = std::env::current_exe().map_err(|_| ProbeError::ContainmentUnavailable)?;
    let mut guardian = Command::new(executable);
    guardian.arg(INTERNAL_GUARDIAN_ARG);
    let outer = ProbePolicy {
        timeout: policy.timeout,
        // The response header is fixed and bounded; the target itself remains
        // subject to the inner policy encoded in the authenticated frame.
        stdout_cap_bytes: policy
            .stdout_cap_bytes
            .checked_add(policy.stderr_cap_bytes)
            .and_then(|bytes| bytes.checked_add(16))
            .filter(|bytes| *bytes <= MAX_GUARDIAN_RESPONSE_BYTES)
            .ok_or(ProbeError::ContainmentUnavailable)?,
        stderr_cap_bytes: policy.stderr_cap_bytes,
        drain_grace: policy.drain_grace,
    };
    let response = run_direct(&mut guardian, outer, cancellation, Some(&frame))?;
    decode_guardian_response(response)
}

#[cfg(unix)]
fn encode_guardian_request(command: &Command, policy: ProbePolicy) -> Result<Vec<u8>, ProbeError> {
    use std::os::unix::ffi::OsStrExt as _;

    let program = command.get_program().as_bytes();
    let args: Vec<&[u8]> = command.get_args().map(|arg| arg.as_bytes()).collect();
    if program.is_empty()
        || program.len() > u16::MAX as usize
        || args.len() > u8::MAX as usize
        || !is_fixed_probe_argv(&args.iter().map(|arg| arg.to_vec()).collect::<Vec<_>>())
    {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let timeout = u64::try_from(policy.timeout.as_millis())
        .map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stdout =
        u32::try_from(policy.stdout_cap_bytes).map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stderr =
        u32::try_from(policy.stderr_cap_bytes).map_err(|_| ProbeError::ContainmentUnavailable)?;
    if !policy_is_fixed_usage(policy) {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let arguments_len = args
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
        .ok_or(ProbeError::ContainmentUnavailable)?;
    let capacity = 64_usize
        .checked_add(program.len())
        .and_then(|bytes| bytes.checked_add(arguments_len))
        .ok_or(ProbeError::ContainmentUnavailable)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&GUARDIAN_REQUEST_MAGIC);
    frame.extend_from_slice(&timeout.to_le_bytes());
    frame.extend_from_slice(&stdout.to_le_bytes());
    frame.extend_from_slice(&stderr.to_le_bytes());
    frame.extend_from_slice(&(program.len() as u16).to_le_bytes());
    frame.push(args.len() as u8);
    frame.extend_from_slice(program);
    for argument in args {
        if argument.len() > u16::MAX as usize {
            return Err(ProbeError::ContainmentUnavailable);
        }
        frame.extend_from_slice(&(argument.len() as u16).to_le_bytes());
        frame.extend_from_slice(argument);
    }
    if frame.len() > MAX_GUARDIAN_REQUEST_BYTES {
        return Err(ProbeError::ContainmentUnavailable);
    }
    Ok(frame)
}

#[cfg(unix)]
fn decode_guardian_response(response: ProbeOutput) -> Result<ProbeOutput, ProbeError> {
    let frame = response.stdout;
    if frame.len() < 16 || frame[..4] != GUARDIAN_RESPONSE_MAGIC {
        return Err(ProbeError::ContainmentUnavailable);
    }
    let code = i32::from_le_bytes(
        frame[4..8]
            .try_into()
            .map_err(|_| ProbeError::ContainmentUnavailable)?,
    );
    let stdout_len = usize::try_from(u32::from_le_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| ProbeError::ContainmentUnavailable)?,
    ))
    .map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stderr_len = usize::try_from(u32::from_le_bytes(
        frame[12..16]
            .try_into()
            .map_err(|_| ProbeError::ContainmentUnavailable)?,
    ))
    .map_err(|_| ProbeError::ContainmentUnavailable)?;
    let stdout_end = 16_usize
        .checked_add(stdout_len)
        .ok_or(ProbeError::ContainmentUnavailable)?;
    let end = stdout_end
        .checked_add(stderr_len)
        .ok_or(ProbeError::ContainmentUnavailable)?;
    if end != frame.len() {
        return Err(ProbeError::ContainmentUnavailable);
    }
    if code != 0 {
        return Err(if code == 1 {
            ProbeError::NonZeroExit
        } else {
            ProbeError::ContainmentUnavailable
        });
    }
    Ok(ProbeOutput {
        status: response.status,
        stdout: frame[16..stdout_end].to_vec(),
        stderr: frame[stdout_end..end].to_vec(),
    })
}

// ── Platform containment ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct PlatformContainmentSetup;

#[cfg(target_os = "linux")]
impl PlatformContainmentSetup {
    fn configure(command: &mut Command) -> Result<Self, ProbeError> {
        use std::os::unix::process::CommandExt as _;

        // A process group plus parent-death signal is the safe availability
        // path for this *trusted* local CLI. It is intentionally not described
        // as cgroup-complete containment: a child that calls setsid can escape.
        // Strict Linux cgroup launch is provided by the platform guardian when
        // the surrounding integration elects it; falling back silently to a
        // false whole-tree claim would be worse than this explicit boundary.
        command.process_group(0);
        let expected_parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        Ok(Self {})
    }

    fn activate(self, child: &Child) -> Result<PlatformContainment, ProbeError> {
        let pgid = i32::try_from(child.id()).map_err(|_| ProbeError::ContainmentUnavailable)?;
        Ok(PlatformContainment::LinuxProcessGroup { pgid, armed: true })
    }
}

#[cfg(target_os = "linux")]
enum PlatformContainment {
    LinuxProcessGroup { pgid: i32, armed: bool },
}

#[cfg(target_os = "linux")]
impl PlatformContainment {
    fn terminate(&mut self) {
        let Self::LinuxProcessGroup { pgid, armed } = self;
        if *armed {
            *armed = false;
            // SAFETY: CommandExt::process_group(0) created this dedicated
            // process group. ESRCH after normal exit is harmless.
            unsafe {
                let _ = libc::kill(-*pgid, libc::SIGKILL);
            }
        }
    }

    fn is_empty(&self) -> bool {
        // Linux PGID is a trusted-CLI availability boundary, not a cgroup
        // membership proof. The direct child has been reaped before this point.
        true
    }
}

#[cfg(target_os = "linux")]
impl Drop for PlatformContainment {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
struct PlatformContainmentSetup;

#[cfg(all(unix, not(target_os = "linux")))]
impl PlatformContainmentSetup {
    fn configure(command: &mut Command) -> Result<Self, ProbeError> {
        use std::os::unix::process::CommandExt as _;

        // macOS/BSD has no unprivileged cgroup or PR_SET_PDEATHSIG equivalent.
        // This is a bounded *trusted-process-group* boundary only. A generic
        // parent-liveness guardian may own this group in the GUI integration;
        // never promote this fallback to adversarial whole-tree containment.
        command.process_group(0);
        Ok(Self)
    }

    fn activate(self, child: &Child) -> Result<PlatformContainment, ProbeError> {
        let pgid = i32::try_from(child.id()).map_err(|_| ProbeError::ContainmentUnavailable)?;
        Ok(PlatformContainment { pgid, armed: true })
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
struct PlatformContainment {
    pgid: i32,
    armed: bool,
}

#[cfg(all(unix, not(target_os = "linux")))]
impl PlatformContainment {
    fn terminate(&mut self) {
        if self.armed {
            self.armed = false;
            // SAFETY: the child was started in its own process group. The
            // boundary is intentionally scoped to the trusted local CLI.
            unsafe {
                let _ = libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
    }

    fn is_empty(&self) -> bool {
        // Process groups cannot prove that a malicious setsid descendant did
        // not escape. The reaper therefore never blocks readers on this claim.
        true
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl Drop for PlatformContainment {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(windows)]
struct PlatformContainmentSetup {
    job: WindowsProbeJob,
}

#[cfg(windows)]
impl PlatformContainmentSetup {
    fn configure(command: &mut Command) -> Result<Self, ProbeError> {
        use std::os::windows::process::CommandExt as _;

        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        Ok(Self {
            job: WindowsProbeJob::create()?,
        })
    }

    fn activate(self, child: &Child) -> Result<PlatformContainment, ProbeError> {
        self.job.assign(child)?;
        self.job.resume(child)?;
        Ok(PlatformContainment { job: self.job })
    }
}

#[cfg(windows)]
struct PlatformContainment {
    job: WindowsProbeJob,
}

#[cfg(windows)]
impl PlatformContainment {
    fn terminate(&mut self) {
        self.job.terminate();
    }

    fn is_empty(&self) -> bool {
        self.job.active_processes().unwrap_or(false)
    }
}

#[cfg(windows)]
struct WindowsProbeJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl WindowsProbeJob {
    fn create() -> Result<Self, ProbeError> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(ProbeError::ContainmentUnavailable);
        }
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                Self::raw_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(ProbeError::ContainmentUnavailable);
        }
        Ok(Self { handle })
    }

    fn raw_handle(
        handle: &std::os::windows::io::OwnedHandle,
    ) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle as _;

        handle.as_raw_handle().cast()
    }

    fn assign(&self, child: &Child) -> Result<(), ProbeError> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        if unsafe {
            AssignProcessToJobObject(Self::raw_handle(&self.handle), child.as_raw_handle().cast())
        } == 0
        {
            return Err(ProbeError::ContainmentUnavailable);
        }
        Ok(())
    }

    fn resume(&self, child: &Child) -> Result<(), ProbeError> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::HANDLE;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            #[link_name = "NtResumeProcess"]
            fn nt_resume_process(process_handle: HANDLE) -> i32;
        }
        if unsafe { nt_resume_process(child.as_raw_handle().cast()) } < 0 {
            return Err(ProbeError::ContainmentUnavailable);
        }
        Ok(())
    }

    fn terminate(&self) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        unsafe {
            let _ = TerminateJobObject(Self::raw_handle(&self.handle), 1);
        }
    }

    fn active_processes(&self) -> Result<bool, ProbeError> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0_u32;
        if unsafe {
            QueryInformationJobObject(
                Self::raw_handle(&self.handle),
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &raw mut returned,
            )
        } == 0
        {
            return Err(ProbeError::ContainmentUnavailable);
        }
        Ok(info.ActiveProcesses == 0)
    }
}

#[cfg(windows)]
impl Drop for PlatformContainment {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE covers cancellation/unwind and descendants started
        // before the terminal path obtains the Job handle again.
        self.job.terminate();
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("trusted GUI probe containment is unavailable on this platform");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_reader_keeps_prefix_and_drains_the_rest() {
        let signal = Arc::new(AtomicU8::new(0));
        let captured = drain_capped(&b"abcdef"[..], 3, 1, Arc::clone(&signal)).unwrap();
        assert_eq!(captured.bytes, b"abc");
        assert!(captured.exceeded);
        assert_eq!(signal.load(Ordering::Acquire), 1);
    }

    #[test]
    fn capped_reader_accepts_exact_cap() {
        let captured = drain_capped(&b"abc"[..], 3, 1, Arc::new(AtomicU8::new(0))).unwrap();
        assert_eq!(captured.bytes, b"abc");
        assert!(!captured.exceeded);
    }

    #[test]
    fn cancellation_is_shared_and_monotonic() {
        let cancellation = ProbeCancellation::new();
        let worker = cancellation.clone();
        assert!(!worker.is_cancelled());
        cancellation.cancel();
        assert!(worker.is_cancelled());
    }

    #[test]
    fn reader_handoff_timeout_is_bounded_without_joining() {
        let (_tx, rx) = mpsc::sync_channel::<ReaderResult>(1);
        let started = Instant::now();
        assert!(recv_before(&rx, Instant::now() + Duration::from_millis(15)).is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn error_copy_never_includes_tool_output() {
        assert_eq!(
            ProbeError::TimedOut.as_static_message(),
            "usage probe timed out"
        );
        assert_eq!(
            ProbeError::OutputTooLarge { stream: "stderr" }.as_static_message(),
            "usage probe output exceeded limit"
        );
    }

    #[test]
    fn guardian_accepts_only_the_fixed_d2_dashboard_forms() {
        assert!(is_fixed_probe_argv(&[
            b"meter".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
        ]));
        assert!(is_fixed_probe_argv(&[
            b"cost".to_vec(),
            b"top-sessions".to_vec(),
            b"--output".to_vec(),
            b"json".to_vec(),
        ]));
        assert!(is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--days".to_vec(),
            b"1".to_vec(),
        ]));
        assert!(is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--since-unix".to_vec(),
            b"1".to_vec(),
            b"--until-unix".to_vec(),
            b"2".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"meter".to_vec(),
            b"--help".to_vec()
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"cost".to_vec(),
            b"top-sessions".to_vec(),
            b"--output".to_vec(),
            b"json".to_vec(),
            b"--limit".to_vec(),
            b"999".to_vec(),
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--help".to_vec()
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--since-unix".to_vec(),
            b"not-a-time".to_vec(),
            b"--until-unix".to_vec(),
            b"2".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--since-unix".to_vec(),
            Vec::new(),
            b"--until-unix".to_vec(),
            b"2".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
        ]));
        assert!(!is_fixed_probe_argv(&[
            b"usage".to_vec(),
            b"--since-unix".to_vec(),
            b"3".to_vec(),
            b"--until-unix".to_vec(),
            b"2".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
        ]));

        let mut meter = Command::new("neoth");
        meter.args(["meter", "--format", "json"]);
        assert!(is_fixed_probe_command(&meter));
        let mut sessions = Command::new("neoth");
        sessions.args(["cost", "top-sessions", "--output", "json"]);
        assert!(is_fixed_probe_command(&sessions));
        let mut daily = Command::new("neoth");
        daily.args(["usage", "--format", "json", "--days", "1"]);
        assert!(is_fixed_probe_command(&daily));
        let mut injected = Command::new("neoth");
        injected.args(["usage", "--format", "json", "--days", "1", "--help"]);
        assert!(!is_fixed_probe_command(&injected));
        let mut signed_timestamp = Command::new("neoth");
        signed_timestamp.args([
            "usage",
            "--since-unix",
            "+1",
            "--until-unix",
            "2",
            "--format",
            "json",
        ]);
        assert!(!is_fixed_probe_command(&signed_timestamp));
    }

    #[test]
    fn fixed_policy_is_server_owned_and_cannot_be_widened() {
        let fixed = fixed_usage_probe_policy();
        assert!(policy_is_fixed_usage(fixed));
        assert!(!policy_is_fixed_usage(ProbePolicy {
            stdout_cap_bytes: fixed.stdout_cap_bytes + 1,
            ..fixed
        }));
        assert!(!policy_is_fixed_usage(ProbePolicy {
            timeout: fixed.timeout + Duration::from_millis(1),
            ..fixed
        }));
    }

    #[test]
    fn source_keeps_no_network_surface_and_no_unbounded_reader_join() {
        let source = include_str!("trusted_probe_supervisor.rs");
        for forbidden in [
            concat!("std", "::net"),
            concat!("tokio", "::net"),
            concat!("req", "west"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
        ] {
            assert!(
                !source.contains(forbidden),
                "probe supervisor must not add network access: {forbidden}"
            );
        }
        assert!(source.contains("transfer_to_reaper"));
        assert!(source.contains("recv_before"));
        assert!(source.contains("terminate_boundary"));
        assert!(source.contains("guardian_program_is_trusted"));
        assert!(source.contains("canonical_trusted_sibling"));
        assert!(source.contains("policy_is_fixed_usage"));
        assert!(source.contains("checked_add(policy.timeout)"));
        assert!(source.contains("checked_add(policy.drain_grace)"));
        assert!(source.contains("!guardian_program_is_trusted(command.get_program())"));
        assert!(source.contains("if arguments.next().is_some()"));
        assert!(
            !source
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .contains(".expect(")
        );
        for capability in [
            "NEOTH_GUI_READY_FILE",
            "NEOTH_GUI_READY_TOKEN",
            "NEOTH_GUI_PARENT_COMMIT",
            "NEOTH_PRODUCT_LAUNCHER",
            "NEOTH_READY_FILE",
            "NEOTH_READY_TOKEN",
            "NEOTH_INTERFACE",
        ] {
            assert!(source.contains(capability));
        }
        for fixed_environment in ["NO_COLOR", "RUST_LOG_STYLE", "CLICOLOR", "NEOTH_LOG"] {
            assert!(source.contains(fixed_environment));
        }
    }
}
