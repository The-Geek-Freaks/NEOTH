//! Process-tree containment for the private owned updater helper.
//!
//! This module owns the child, its tree guard, and every pipe task until the
//! caller observes a terminal result. A deadline is not terminal: the caller
//! retains this value, records cancellation, then asks it to reap.

#[cfg(test)]
use std::path::PathBuf;

use std::{
    ffi::OsString,
    path::Path,
    process::ExitStatus,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

#[cfg(windows)]
use cap_fs_ext::DirExt as _;
#[cfg(windows)]
use cap_fs_ext::MetadataExt as _;
#[cfg(windows)]
use cap_std::fs::Dir;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(2);

// Test-only argument selection for one exact, already verified native fixture
// image. The W40 production path still receives only `--version`; this exists
// solely because the production test binary can exceed the 256 MiB descriptor
// cap and therefore cannot itself be used as the contained native image.
#[cfg(test)]
static NATIVE_CLI_VERSION_TEST_HELPERS: std::sync::Mutex<Vec<NativeCliVersionTestHelper>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone)]
struct NativeCliVersionTestHelper {
    program: PathBuf,
    argv: Vec<OsString>,
    launches: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    observed: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
pub(crate) struct NativeCliVersionTestHelperGuard(PathBuf);

#[cfg(test)]
impl Drop for NativeCliVersionTestHelperGuard {
    fn drop(&mut self) {
        let mut helpers = NATIVE_CLI_VERSION_TEST_HELPERS
            .lock()
            .expect("native CLI helper registry");
        helpers.retain(|helper| helper.program != self.0);
    }
}

#[cfg(test)]
pub(crate) fn enable_native_cli_version_test_helper(
    program: &Path,
    argv: Vec<OsString>,
    launches: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    observed: std::sync::Arc<tokio::sync::Notify>,
) -> NativeCliVersionTestHelperGuard {
    let program = program.to_path_buf();
    let mut helpers = NATIVE_CLI_VERSION_TEST_HELPERS
        .lock()
        .expect("native CLI helper registry");
    assert!(
        !helpers.iter().any(|helper| helper.program == program),
        "native CLI helper program is already registered"
    );
    helpers.push(NativeCliVersionTestHelper {
        program: program.clone(),
        argv,
        launches,
        observed,
    });
    NativeCliVersionTestHelperGuard(program)
}

#[cfg(test)]
fn native_cli_version_test_helper(program: &Path) -> Option<NativeCliVersionTestHelper> {
    NATIVE_CLI_VERSION_TEST_HELPERS
        .lock()
        .expect("native CLI helper registry")
        .iter()
        .find(|helper| helper.program == program)
        .cloned()
}

#[derive(Debug)]
pub(crate) enum ContainedChildError {
    Setup(anyhow::Error),
    DeadlineElapsed,
    TreeTermination(anyhow::Error),
    ChildReap(std::io::Error),
    OutputTooLarge {
        stream: &'static str,
        max_bytes: usize,
    },
    PipeRead {
        stream: &'static str,
        error: std::io::Error,
    },
    WorkerPanicked {
        worker: &'static str,
    },
    WorkerTimedOut {
        worker: &'static str,
    },
    Stdin(std::io::Error),
}

impl std::fmt::Display for ContainedChildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(error) => write!(
                formatter,
                "contained updater helper setup failed: {error:#}"
            ),
            Self::DeadlineElapsed => write!(formatter, "contained updater helper deadline elapsed"),
            Self::TreeTermination(error) => write!(
                formatter,
                "terminate contained updater helper tree: {error:#}"
            ),
            Self::ChildReap(error) => write!(formatter, "reap contained updater helper: {error}"),
            Self::OutputTooLarge { stream, max_bytes } => write!(
                formatter,
                "contained updater helper {stream} exceeded {max_bytes} bytes"
            ),
            Self::PipeRead { stream, error } => {
                write!(formatter, "read contained updater helper {stream}: {error}")
            }
            Self::WorkerPanicked { worker } => write!(
                formatter,
                "contained updater helper {worker} worker panicked"
            ),
            Self::WorkerTimedOut { worker } => write!(
                formatter,
                "contained updater helper {worker} worker did not finish after containment"
            ),
            Self::Stdin(error) => write!(formatter, "write exact updater helper stdin: {error}"),
        }
    }
}

impl std::error::Error for ContainedChildError {}

#[derive(Debug)]
pub(crate) struct ContainedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    #[cfg(test)]
    pub(crate) stderr: Vec<u8>,
}

#[derive(Debug)]
struct ReadOutput {
    bytes: Vec<u8>,
    exceeded_cap: bool,
}

type ReaderTask = tokio::task::JoinHandle<std::io::Result<ReadOutput>>;
type WriterTask = tokio::task::JoinHandle<std::io::Result<()>>;

/// Owns an exact command invocation and its OS process-tree boundary.
///
/// Dropping it is fail-closed: it signals the boundary and aborts owned I/O
/// tasks, but cannot report successful reaping. Normal updater paths must
/// await `wait_until` or `terminate_and_reap` before classifying the outcome.
pub(crate) struct ContainedChild {
    child: Option<tokio::process::Child>,
    #[cfg(unix)]
    group: UnixProcessGroup,
    #[cfg(windows)]
    job: WindowsProcessJob,
    stdout: Option<ReaderTask>,
    stderr: Option<ReaderTask>,
    stdin: Option<WriterTask>,
    output_cap: usize,
    // The directory capability which selected the child's CWD stays alive
    // until this owner has reaped the whole contained process tree.
    _retained_working_directory: Option<RetainedWorkingDirectory>,
}

#[cfg(unix)]
struct RetainedWorkingDirectory {
    _directory: cap_std::fs::Dir,
}

#[cfg(windows)]
struct RetainedWorkingDirectory {
    // `Dir` deliberately excludes FILE_SHARE_DELETE on Windows. Holding the
    // full root-to-leaf chain prevents a `current_dir` path component from
    // being renamed/replaced between its no-follow binding and CreateProcess.
    _ancestors: Vec<Dir>,
    _directory: Dir,
}

impl ContainedChild {
    pub(crate) async fn spawn(
        program: &Path,
        argv: &[OsString],
        exact_stdin: &[u8],
        output_cap: usize,
    ) -> std::result::Result<Self, ContainedChildError> {
        let mut command = tokio::process::Command::new(program);
        command.args(argv);
        Self::spawn_configured(command, exact_stdin, output_cap).await
    }

    /// The sole sterile launch variant, restricted to native managed CLI
    /// version probes. It changes only command hygiene before the common
    /// contained-child setup path; tree activation and cleanup stay shared.
    pub(crate) async fn spawn_native_cli_version(
        program: &Path,
        argv: &[OsString],
        working_directory: &Path,
        output_cap: usize,
    ) -> std::result::Result<Self, ContainedChildError> {
        let mut command = tokio::process::Command::new(program);
        command.current_dir(working_directory).env_clear();
        #[cfg(test)]
        let helper = native_cli_version_test_helper(program);
        #[cfg(test)]
        if let Some(helper) = helper.as_ref() {
            command.args(&helper.argv);
        } else {
            command.args(argv);
        }
        #[cfg(not(test))]
        command.args(argv);
        #[cfg(windows)]
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        #[cfg(test)]
        if let Some(helper) = helper {
            // This is the test's launch boundary: the counter advances only
            // immediately before the real ContainedChild spawn path.
            helper
                .launches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            helper.observed.notify_one();
        }
        Self::spawn_configured(command, &[], output_cap).await
    }

    /// Launch inside a retained real-directory capability. This is the only
    /// contained-child variant for an externally selected working directory.
    ///
    /// Unix changes the child directory through `fchdir` in the post-fork,
    /// pre-exec hook. Windows has no CreateProcess directory-handle argument,
    /// so it retains a no-follow disk-root-to-leaf `Dir` chain which denies
    /// delete sharing while the display path is supplied to CreateProcess.
    pub(crate) async fn spawn_in_retained_directory(
        mut command: tokio::process::Command,
        directory: &cap_std::fs::Dir,
        display_path: &Path,
        exact_stdin: &[u8],
        output_cap: usize,
    ) -> std::result::Result<Self, ContainedChildError> {
        let retained = configure_retained_working_directory(&mut command, directory, display_path)
            .map_err(ContainedChildError::Setup)?;
        Self::spawn_configured_with_retained(command, exact_stdin, output_cap, Some(retained)).await
    }

    /// Launch a caller-configured command through the same owned process-tree
    /// and pipe lifecycle. Callers select the working directory and environment;
    /// this function retains control of stdio, containment, and child cleanup.
    pub(crate) async fn spawn_configured(
        command: tokio::process::Command,
        exact_stdin: &[u8],
        output_cap: usize,
    ) -> std::result::Result<Self, ContainedChildError> {
        Self::spawn_configured_with_retained(command, exact_stdin, output_cap, None).await
    }

    async fn spawn_configured_with_retained(
        mut command: tokio::process::Command,
        exact_stdin: &[u8],
        output_cap: usize,
        retained_working_directory: Option<RetainedWorkingDirectory>,
    ) -> std::result::Result<Self, ContainedChildError> {
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        configure_process_tree(&mut command);

        let child = command
            .spawn()
            .map_err(|error| ContainedChildError::Setup(anyhow::Error::new(error)))?;

        let mut pending = PendingContainedChild::new(child);
        #[cfg(unix)]
        {
            // `process_group(0)` took effect in spawn. Capture the PGID before
            // even a test-injected post-spawn fault so descendants cannot
            // escape the direct-leader cleanup path.
            pending.group = match UnixProcessGroup::from_child(&pending.child) {
                Ok(group) => Some(group),
                Err(error) => return Err(pending.setup_failure(error).await),
            };
        }
        if let Err(error) = inject_setup_fault(SetupFaultPoint::AfterSpawn) {
            return Err(pending.setup_failure(error).await);
        }

        // Windows begins suspended and is assigned to KILL_ON_JOB_CLOSE before
        // it resumes. Unix starts in its own process group. Every failure after
        // the OS spawn enters the awaited setup cleanup path below.
        #[cfg(windows)]
        {
            let job = match WindowsProcessJob::create() {
                Ok(job) => job,
                Err(error) => return Err(pending.setup_failure(error).await),
            };
            pending.job = Some(job);
            let activation = pending
                .job
                .as_ref()
                .expect("new Job Object remains owned by setup")
                .assign(&pending.child)
                .and_then(|()| {
                    pending
                        .job
                        .as_ref()
                        .expect("assigned Job Object remains owned by setup")
                        .resume(&pending.child)
                });
            if let Err(error) = activation {
                return Err(pending.setup_failure(error).await);
            }
        }
        if let Err(error) = inject_setup_fault(SetupFaultPoint::AfterTreeActivation) {
            return Err(pending.setup_failure(error).await);
        }

        // No pipe task is created until every handle has been acquired. On a
        // setup invariant failure the armed group/job plus child own teardown,
        // so no reader can be detached on an error path.
        if let Err(error) = inject_setup_fault(SetupFaultPoint::BeforeStdoutTake) {
            return Err(pending.setup_failure(error).await);
        }
        let stdout = match pending.child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                return Err(pending
                    .setup_failure(anyhow::anyhow!("contained helper stdout pipe missing"))
                    .await);
            }
        };
        if let Err(error) = inject_setup_fault(SetupFaultPoint::BeforeStderrTake) {
            return Err(pending.setup_failure(error).await);
        }
        let stderr = match pending.child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                return Err(pending
                    .setup_failure(anyhow::anyhow!("contained helper stderr pipe missing"))
                    .await);
            }
        };
        if let Err(error) = inject_setup_fault(SetupFaultPoint::BeforeStdinTake) {
            return Err(pending.setup_failure(error).await);
        }
        let stdin = match pending.child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                return Err(pending
                    .setup_failure(anyhow::anyhow!("contained helper stdin pipe missing"))
                    .await);
            }
        };

        let ReadyContainedTree {
            child,
            #[cfg(unix)]
            group,
            #[cfg(windows)]
            job,
        } = pending.into_ready();

        let stdin_bytes = exact_stdin.to_vec();
        Ok(Self {
            child: Some(child),
            #[cfg(unix)]
            group,
            #[cfg(windows)]
            job,
            stdout: Some(tokio::spawn(read_capped(stdout, output_cap))),
            stderr: Some(tokio::spawn(read_capped(stderr, output_cap))),
            stdin: Some(tokio::spawn(async move {
                let mut stdin = stdin;
                stdin.write_all(&stdin_bytes).await?;
                stdin.shutdown().await
            })),
            output_cap,
            _retained_working_directory: retained_working_directory,
        })
    }

    /// Wait for the leader. On deadline every owned resource remains present.
    pub(crate) async fn wait_until(
        &mut self,
        deadline: Instant,
    ) -> std::result::Result<ContainedOutput, ContainedChildError> {
        loop {
            let exit_status = match self.child_mut().try_wait() {
                Ok(exit_status) => exit_status,
                Err(wait_error) => {
                    // A wait error is never allowed to strand a child or a
                    // reader. Attempt the same full cleanup path before the
                    // caller receives the original observation failure.
                    match self.terminate_and_reap().await {
                        Ok(_) => return Err(ContainedChildError::ChildReap(wait_error)),
                        Err(cleanup_error) => return Err(cleanup_error),
                    }
                }
            };
            if let Some(exit_status) = exit_status {
                return self.finish_after_leader_exit(exit_status).await;
            }
            if Instant::now() >= deadline {
                return Err(ContainedChildError::DeadlineElapsed);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Kill the complete tree, reap the leader, and await every owned pipe.
    ///
    /// Tree termination takes precedence over all other results. If it fails,
    /// descendants may survive and callers must classify the result as
    /// indeterminate even where the direct child and all local tasks ended.
    pub(crate) async fn terminate_and_reap(
        &mut self,
    ) -> std::result::Result<ContainedOutput, ContainedChildError> {
        let tree_result = self.terminate_tree();
        let leader_result = self.kill_and_reap_leader().await;
        let pipes_result = self.collect_pipes().await;

        if let Err(error) = tree_result {
            return Err(ContainedChildError::TreeTermination(error));
        }
        let status = leader_result?;
        let (stdout, stderr) = pipes_result?;
        #[cfg(not(test))]
        drop(stderr);
        Ok(ContainedOutput {
            status,
            stdout,
            #[cfg(test)]
            stderr,
        })
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("contained updater child remains owned until reaped")
    }

    fn terminate_tree(&mut self) -> Result<()> {
        #[cfg(unix)]
        self.group.terminate()?;
        #[cfg(windows)]
        self.job.terminate()?;
        Ok(())
    }

    async fn finish_after_leader_exit(
        &mut self,
        status: ExitStatus,
    ) -> std::result::Result<ContainedOutput, ContainedChildError> {
        self.child = None;
        let tree_result = self.terminate_tree();
        let pipes_result = self.collect_pipes().await;
        if let Err(error) = tree_result {
            return Err(ContainedChildError::TreeTermination(error));
        }
        let (stdout, stderr) = pipes_result?;
        #[cfg(not(test))]
        drop(stderr);
        Ok(ContainedOutput {
            status,
            stdout,
            #[cfg(test)]
            stderr,
        })
    }

    async fn kill_and_reap_leader(
        &mut self,
    ) -> std::result::Result<ExitStatus, ContainedChildError> {
        let Some(mut child) = self.child.take() else {
            return Err(ContainedChildError::ChildReap(std::io::Error::other(
                "contained updater helper leader was already released",
            )));
        };
        match child.try_wait() {
            Ok(Some(status)) => Ok(status),
            Ok(None) => {
                // The tree guard should already have killed the leader. Keep a
                // checked direct kill as a second boundary for a process that
                // escaped its group/job setup.
                if let Err(error) = child.start_kill() {
                    match child.try_wait() {
                        Ok(Some(status)) => Ok(status),
                        _ => Err(ContainedChildError::ChildReap(error)),
                    }
                } else {
                    child.wait().await.map_err(ContainedChildError::ChildReap)
                }
            }
            Err(error) => Err(ContainedChildError::ChildReap(error)),
        }
    }

    async fn collect_pipes(
        &mut self,
    ) -> std::result::Result<(Vec<u8>, Vec<u8>), ContainedChildError> {
        let stdout_task = self.stdout.take().expect("stdout task is owned once");
        let stderr_task = self.stderr.take().expect("stderr task is owned once");
        let stdin_task = self.stdin.take().expect("stdin task is owned once");

        // Do not `?` until every task reached a terminal state. A descendant
        // may inherit a pipe after its leader exits; timeout aborts and awaits
        // that exact task after the tree guard has been signalled.
        let stdout_result = join_reader(stdout_task, "stdout").await;
        let stderr_result = join_reader(stderr_task, "stderr").await;
        let stdin_result = join_stdin(stdin_task).await;

        let stdout = stdout_result?;
        let stderr = stderr_result?;
        stdin_result?;
        if stdout.exceeded_cap {
            return Err(ContainedChildError::OutputTooLarge {
                stream: "stdout",
                max_bytes: self.output_cap,
            });
        }
        if stderr.exceeded_cap {
            return Err(ContainedChildError::OutputTooLarge {
                stream: "stderr",
                max_bytes: self.output_cap,
            });
        }
        // Output remains private to the contained owner and is returned only after
        // the group/job, leader and both pipe workers reached terminal state.
        Ok((stdout.bytes, stderr.bytes))
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum SetupFaultPoint {
    AfterSpawn = 1,
    AfterTreeActivation = 2,
    BeforeStdoutTake = 3,
    BeforeStderrTake = 4,
    BeforeStdinTake = 5,
}

#[cfg(not(test))]
fn inject_setup_fault(_: SetupFaultPoint) -> Result<()> {
    Ok(())
}

#[cfg(test)]
static SETUP_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
static SETUP_CLEANUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn inject_setup_fault(point: SetupFaultPoint) -> Result<()> {
    if SETUP_FAULT.load(std::sync::atomic::Ordering::SeqCst) == point as u8 {
        anyhow::bail!(
            "injected contained-helper setup fault at point {}",
            point as u8
        );
    }
    Ok(())
}

/// Exists only between a successful OS spawn and reader-task creation. It is
/// deliberately narrow so all post-spawn setup failures have one awaited
/// cleanup owner and cannot fall through to `ContainedChild::Drop`.
struct PendingContainedChild {
    child: tokio::process::Child,
    #[cfg(unix)]
    group: Option<UnixProcessGroup>,
    #[cfg(windows)]
    job: Option<WindowsProcessJob>,
}

impl PendingContainedChild {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child,
            #[cfg(unix)]
            group: None,
            #[cfg(windows)]
            job: None,
        }
    }

    async fn setup_failure(mut self, setup_error: anyhow::Error) -> ContainedChildError {
        let tree_result = self.terminate_tree();
        let leader_result = self.kill_and_reap_leader().await;
        #[cfg(test)]
        SETUP_CLEANUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match (tree_result, leader_result) {
            (Ok(()), Ok(())) => ContainedChildError::Setup(setup_error),
            (Err(tree_error), Ok(())) => ContainedChildError::Setup(setup_error.context(format!(
                "setup cleanup could not terminate contained process tree: {tree_error:#}"
            ))),
            (Ok(()), Err(leader_error)) => ContainedChildError::Setup(setup_error.context(
                format!("setup cleanup could not kill and reap contained leader: {leader_error}"),
            )),
            (Err(tree_error), Err(leader_error)) => {
                ContainedChildError::Setup(setup_error.context(format!(
                    "setup cleanup failed for tree ({tree_error:#}) and leader ({leader_error})"
                )))
            }
        }
    }

    fn into_ready(self) -> ReadyContainedTree {
        ReadyContainedTree {
            child: self.child,
            #[cfg(unix)]
            group: self
                .group
                .expect("Unix process group activated before pipe tasks"),
            #[cfg(windows)]
            job: self
                .job
                .expect("Windows Job Object activated before pipe tasks"),
        }
    }

    fn terminate_tree(&mut self) -> Result<()> {
        #[cfg(unix)]
        if let Some(group) = self.group.as_mut() {
            group.terminate()?;
        }
        #[cfg(windows)]
        if let Some(job) = self.job.as_ref() {
            job.terminate()?;
        }
        Ok(())
    }

    async fn kill_and_reap_leader(&mut self) -> std::io::Result<()> {
        match self.child.try_wait()? {
            Some(_) => Ok(()),
            None => {
                if let Err(error) = self.child.start_kill() {
                    if self.child.try_wait()?.is_none() {
                        return Err(error);
                    }
                    return Ok(());
                }
                self.child.wait().await.map(|_| ())
            }
        }
    }
}

struct ReadyContainedTree {
    child: tokio::process::Child,
    #[cfg(unix)]
    group: UnixProcessGroup,
    #[cfg(windows)]
    job: WindowsProcessJob,
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        // Drop cannot await terminal proof. It only signals containment and
        // cancels owned tasks; it never manufactures a quiet success outcome.
        let _ = self.terminate_tree();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        abort_owned_task(self.stdout.take());
        abort_owned_task(self.stderr.take());
        abort_owned_task(self.stdin.take());
    }
}

fn abort_owned_task<T>(task: Option<tokio::task::JoinHandle<T>>) {
    if let Some(task) = task {
        // Drop has no async context to await cancellation acknowledgement.
        // This is emergency signal-only cleanup, never normal lifecycle
        // ownership and never evidence that pipes or the child were reaped.
        task.abort();
    }
}

async fn read_capped<R>(mut reader: R, cap: usize) -> std::io::Result<ReadOutput>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut exceeded_cap = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(ReadOutput {
                bytes,
                exceeded_cap,
            });
        }
        let accepted = cap.saturating_sub(bytes.len()).min(count);
        bytes.extend_from_slice(&buffer[..accepted]);
        exceeded_cap |= accepted < count;
    }
}

async fn join_reader(
    mut task: ReaderTask,
    stream: &'static str,
) -> std::result::Result<ReadOutput, ContainedChildError> {
    match tokio::time::timeout(PIPE_DRAIN_GRACE, &mut task).await {
        Ok(Ok(Ok(output))) => Ok(output),
        Ok(Ok(Err(error))) => Err(ContainedChildError::PipeRead { stream, error }),
        Ok(Err(_)) => Err(ContainedChildError::WorkerPanicked { worker: stream }),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ContainedChildError::WorkerTimedOut { worker: stream })
        }
    }
}

async fn join_stdin(mut task: WriterTask) -> std::result::Result<(), ContainedChildError> {
    match tokio::time::timeout(PIPE_DRAIN_GRACE, &mut task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(ContainedChildError::Stdin(error)),
        Ok(Err(_)) => Err(ContainedChildError::WorkerPanicked { worker: "stdin" }),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ContainedChildError::WorkerTimedOut { worker: "stdin" })
        }
    }
}

#[cfg(unix)]
fn configure_retained_working_directory(
    command: &mut tokio::process::Command,
    directory: &cap_std::fs::Dir,
    _display_path: &Path,
) -> Result<RetainedWorkingDirectory> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;

    // One clone is captured by the pre-exec hook, where its descriptor names
    // the exact opened directory even if its namespace path is renamed. A
    // second clone stays in the eventual ContainedChild through tree teardown.
    let pre_exec_directory = directory
        .try_clone()
        .context("clone retained contained-child working directory for fchdir")?;
    let retained_directory = directory
        .try_clone()
        .context("retain contained-child working directory through teardown")?;
    // SAFETY: the hook makes only async-signal-safe `fchdir` and, on failure,
    // reads the thread-local OS error for the immediate spawn error path. The
    // captured directory FD remains live until exec because the closure owns it.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::fchdir(pre_exec_directory.as_raw_fd()) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(RetainedWorkingDirectory {
        _directory: retained_directory,
    })
}

#[cfg(windows)]
fn configure_retained_working_directory(
    command: &mut tokio::process::Command,
    directory: &Dir,
    display_path: &Path,
) -> Result<RetainedWorkingDirectory> {
    use cap_std::fs::MetadataExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::path::{Component, Prefix};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let absolute = std::path::absolute(display_path).with_context(|| {
        format!(
            "resolve retained contained-child working directory {}",
            display_path.display()
        )
    })?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        anyhow::bail!(
            "retained contained-child working directory lacks a disk root: {}",
            display_path.display()
        );
    };
    let (letter, verbatim_disk) = match prefix.kind() {
        Prefix::Disk(letter) => (letter, false),
        // `std::fs::canonicalize` produces this prefix for the physical
        // Windows display paths retained by the capability store.
        Prefix::VerbatimDisk(letter) => (letter, true),
        _ => anyhow::bail!(
            "retained contained-child working directory has an unsupported namespace: {}",
            display_path.display()
        ),
    };
    anyhow::ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "retained contained-child working directory is not absolute: {}",
        display_path.display()
    );

    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => anyhow::bail!(
                "retained contained-child working directory has a non-child component: {}",
                display_path.display()
            ),
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        !names.is_empty(),
        "retained contained-child working directory must not be a disk root: {}",
        display_path.display()
    );

    let disk_root = std::path::PathBuf::from(if verbatim_disk {
        format!(r"\\?\{}:\", char::from(letter))
    } else {
        format!("{}:\\", char::from(letter))
    });
    let mut root_options = std::fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let root_file = root_options.open(&disk_root).with_context(|| {
        format!(
            "open disk root for retained contained-child working directory {}",
            display_path.display()
        )
    })?;
    let root_metadata = root_file.metadata().with_context(|| {
        format!(
            "inspect disk root for retained contained-child working directory {}",
            display_path.display()
        )
    })?;
    anyhow::ensure!(
        root_metadata.is_dir()
            && std::os::windows::fs::MetadataExt::file_attributes(&root_metadata)
                & FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
        "retained contained-child disk root is not a real directory: {}",
        display_path.display()
    );

    let mut parent = Dir::from_std_file(root_file);
    let mut retained_ancestors = Vec::with_capacity(names.len());
    for name in &names[..names.len() - 1] {
        let next = parent.open_dir_nofollow(name).with_context(|| {
            format!(
                "open retained contained-child ancestor without following links {}",
                display_path.display()
            )
        })?;
        let metadata = next.dir_metadata().with_context(|| {
            format!(
                "inspect retained contained-child ancestor {}",
                display_path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "retained contained-child ancestor is not a real directory: {}",
            display_path.display()
        );
        retained_ancestors.push(parent);
        parent = next;
    }

    let final_name = names.last().expect("non-empty child component list");
    let (retained_directory, _binding) = crate::skills::store::bind_retained_real_child_dir(
        &parent,
        final_name,
        display_path,
        directory
            .try_clone()
            .context("clone retained contained-child working directory")?,
    )?;
    retained_ancestors.push(parent);
    command.current_dir(display_path);
    Ok(RetainedWorkingDirectory {
        _ancestors: retained_ancestors,
        _directory: retained_directory,
    })
}

#[cfg(unix)]
fn configure_process_tree(command: &mut tokio::process::Command) {
    use std::os::unix::process::CommandExt as _;
    command.as_std_mut().process_group(0);
}

#[cfg(windows)]
fn configure_process_tree(command: &mut tokio::process::Command) {
    use std::os::windows::process::CommandExt as _;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command
        .as_std_mut()
        .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
}

#[cfg(unix)]
pub(crate) struct UnixProcessGroup {
    process_group_id: i32,
    armed: bool,
}

#[cfg(unix)]
impl UnixProcessGroup {
    #[cfg(feature = "recursive-mas")]
    pub(crate) fn from_spawned_pid(pid: u32) -> Result<Self> {
        Ok(Self {
            process_group_id: pid
                .try_into()
                .context("contained process-group id does not fit i32")?,
            armed: true,
        })
    }
    fn from_child(child: &tokio::process::Child) -> Result<Self> {
        let process_group_id = child
            .id()
            .context("contained helper exited before process-group activation")?
            .try_into()
            .context("contained helper process-group id does not fit i32")?;
        Ok(Self {
            process_group_id,
            armed: true,
        })
    }

    pub(crate) fn terminate(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        let process_group = self
            .process_group_id
            .checked_neg()
            .context("contained helper process-group id cannot be negated")?;
        // SAFETY: this is the negative PGID captured from a spawn configured
        // with process_group(0); SIGKILL has no Rust memory aliasing effects.
        let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
        if result == 0 {
            self.armed = false;
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            self.armed = false;
            return Ok(());
        }
        // Leave it armed so Drop gets one further fail-closed attempt, while
        // the caller receives the original checked failure.
        Err(error).context("kill contained updater helper process group")
    }
}

#[cfg(unix)]
impl Drop for UnixProcessGroup {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(windows)]
pub(crate) struct WindowsProcessJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtResumeProcess(process_handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
}

#[cfg(windows)]
impl WindowsProcessJob {
    pub(crate) fn create() -> Result<Self> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: null attributes and name create a fresh unnamed Job Object.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            anyhow::bail!(
                "create updater helper Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: this wrapper takes sole ownership of the fresh handle.
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        // SAFETY: zero is a valid initial representation for this Win32 POD.
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: both the handle and the exact POD structure remain live for
        // this synchronous Win32 call.
        if unsafe {
            SetInformationJobObject(
                Self::raw_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            anyhow::bail!(
                "configure updater helper Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { handle })
    }

    fn assign(&self, child: &tokio::process::Child) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        let child_handle = child
            .raw_handle()
            .context("contained helper exited before Job Object assignment")?;
        // SAFETY: both values are live kernel handles during this call.
        if unsafe { AssignProcessToJobObject(Self::raw_handle(&self.handle), child_handle.cast()) }
            == 0
        {
            anyhow::bail!(
                "assign updater helper Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "recursive-mas"), allow(dead_code))]
    pub(crate) fn assign_std_child(&self, child: &std::process::Child) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        self.assign_raw(child.as_raw_handle().cast())
    }

    fn resume(&self, child: &tokio::process::Child) -> Result<()> {
        let child_handle = child
            .raw_handle()
            .context("contained helper exited before suspended-process resume")?;
        // SAFETY: the live process handle belongs to this configured job.
        let status = unsafe { NtResumeProcess(child_handle.cast()) };
        if status < 0 {
            anyhow::bail!(
                "resume updater helper after Job Object assignment: NTSTATUS {status:#x}"
            );
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "recursive-mas"), allow(dead_code))]
    pub(crate) fn resume_std_child(&self, child: &std::process::Child) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        self.resume_raw(child.as_raw_handle().cast())
    }

    #[cfg_attr(not(feature = "recursive-mas"), allow(dead_code))]
    fn assign_raw(&self, child_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(Self::raw_handle(&self.handle), child_handle) } == 0 {
            anyhow::bail!(
                "assign updater helper Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "recursive-mas"), allow(dead_code))]
    fn resume_raw(&self, child_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<()> {
        let status = unsafe { NtResumeProcess(child_handle) };
        if status < 0 {
            anyhow::bail!(
                "resume updater helper after Job Object assignment: NTSTATUS {status:#x}"
            );
        }
        Ok(())
    }

    pub(crate) fn terminate(&self) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: the owned job handle is live. Failure is surfaced because a
        // caller cannot assume the process tree vanished.
        if unsafe { TerminateJobObject(Self::raw_handle(&self.handle), 1) } == 0 {
            anyhow::bail!(
                "terminate updater helper Job Object: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    fn raw_handle(
        handle: &std::os::windows::io::OwnedHandle,
    ) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle as _;
        handle.as_raw_handle().cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static ENVIRONMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn contained_child_grandchild_marker_helper() {
        let Some(marker) = std::env::var_os("NEOTH_TEST_UPDATER_CONTAINED_MARKER") else {
            return;
        };
        std::thread::sleep(Duration::from_millis(700));
        std::fs::write(marker, b"escaped").unwrap();
    }

    // The spawned grandchild must outlive this fast parent so the outer
    // ContainedChild group/job owns and terminates the orphaned descendant.
    // Waiting here would defeat the containment scenario under test.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn contained_child_parent_helper() {
        let Some(marker) = std::env::var_os("NEOTH_TEST_UPDATER_CONTAINED_MARKER") else {
            return;
        };
        let _ = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("contained_child_grandchild_marker_helper")
            .env("NEOTH_TEST_UPDATER_CONTAINED_MARKER", marker)
            .spawn()
            .unwrap();
        if std::env::var_os("NEOTH_TEST_UPDATER_CONTAINED_EXIT_FAST").is_none() {
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn contained_child_retained_cwd_helper() {
        let Some(marker) = std::env::var_os("NEOTH_TEST_UPDATER_RETAINED_CWD_MARKER") else {
            return;
        };
        std::fs::write(
            marker,
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .as_bytes(),
        )
        .unwrap();
    }

    // The process-wide environment and fault injector must remain serialized
    // through the awaited child lifecycle; this guard is deliberate test-only
    // ownership, not production synchronization.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn deadline_reap_kills_actual_descendant() {
        let _environment = ENVIRONMENT.lock().unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let marker = tempdir.path().join("marker");
        unsafe { std::env::set_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER", &marker) };
        let args = vec![OsString::from("contained_child_parent_helper")];
        let mut child = ContainedChild::spawn(&std::env::current_exe().unwrap(), &args, b"", 1024)
            .await
            .unwrap();
        assert!(matches!(
            child
                .wait_until(Instant::now() + Duration::from_millis(100))
                .await,
            Err(ContainedChildError::DeadlineElapsed)
        ));
        child.terminate_and_reap().await.unwrap();
        unsafe { std::env::remove_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER") };
        std::thread::sleep(Duration::from_millis(900));
        assert!(!marker.exists(), "descendant escaped timeout containment");
    }

    // The process-wide environment must remain serialized through the awaited
    // helper lifecycle so a sibling test cannot inherit its marker variables.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn fast_leader_closes_inherited_pipe_descendant() {
        let _environment = ENVIRONMENT.lock().unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let marker = tempdir.path().join("marker");
        unsafe {
            std::env::set_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER", &marker);
            std::env::set_var("NEOTH_TEST_UPDATER_CONTAINED_EXIT_FAST", "1");
        }
        let args = vec![OsString::from("contained_child_parent_helper")];
        let mut child = ContainedChild::spawn(&std::env::current_exe().unwrap(), &args, b"", 1024)
            .await
            .unwrap();
        assert!(
            child
                .wait_until(Instant::now() + Duration::from_secs(2))
                .await
                .unwrap()
                .status
                .success()
        );
        unsafe {
            std::env::remove_var("NEOTH_TEST_UPDATER_CONTAINED_EXIT_FAST");
            std::env::remove_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER");
        }
        std::thread::sleep(Duration::from_millis(900));
        assert!(!marker.exists(), "fast leader left descendant");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retained_directory_cwd_survives_namespace_rename_before_spawn() {
        let _environment = ENVIRONMENT.lock().unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let original = tempdir.path().join("repository");
        let moved = tempdir.path().join("repository-moved");
        let marker = tempdir.path().join("retained-cwd.txt");
        std::fs::create_dir(&original).unwrap();
        let directory = cap_std::fs::Dir::from_std_file(std::fs::File::open(&original).unwrap());
        std::fs::rename(&original, &moved).unwrap();

        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("contained_child_retained_cwd_helper")
            .env("NEOTH_TEST_UPDATER_RETAINED_CWD_MARKER", &marker);
        let mut child = ContainedChild::spawn_in_retained_directory(
            command,
            &directory,
            &original,
            b"",
            8 * 1024,
        )
        .await
        .unwrap();
        let output = child
            .wait_until(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(output.status.success());
        let observed = std::fs::canonicalize(std::fs::read_to_string(marker).unwrap()).unwrap();
        let expected = std::fs::canonicalize(&moved).unwrap();
        assert_eq!(
            observed,
            expected,
            "the child must enter the retained directory object, not the stale name"
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_directory_windows_accepts_canonical_path_and_refuses_distinct_capability() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("root");
        let repository = root.join("repository");
        let replacement = root.join("replacement");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&repository).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let open_directory = |path: &Path| {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
            Dir::from_std_file(options.open(path).unwrap())
        };
        let original = open_directory(&repository);
        let replacement = open_directory(&replacement);
        let canonical_repository = std::fs::canonicalize(&repository).unwrap();

        let mut command = tokio::process::Command::new("cmd.exe");
        let retained =
            configure_retained_working_directory(&mut command, &original, &canonical_repository)
                .expect(
                    "canonical physical repository path should bind to its retained capability",
                );
        let mut mismatch_command = tokio::process::Command::new("cmd.exe");
        assert!(
            configure_retained_working_directory(
                &mut mismatch_command,
                &replacement,
                &canonical_repository,
            )
            .is_err(),
            "a distinct retained directory must not bind to the canonical repository namespace"
        );
        drop(retained);
    }

    #[tokio::test]
    async fn missing_executable_returns_setup_error() {
        let missing = std::env::temp_dir().join(format!("neoth-missing-{}", std::process::id()));
        assert!(matches!(
            ContainedChild::spawn(&missing, &[], b"", 64).await,
            Err(ContainedChildError::Setup(_))
        ));
    }

    // This holds the process-wide test fault switch through each awaited setup
    // cleanup so another test cannot observe a synthetic fault.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn every_post_spawn_setup_fault_reaps_the_leader_before_setup_returns() {
        let _environment = ENVIRONMENT.lock().unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let args = vec![OsString::from("contained_child_parent_helper")];
        let cleanup_start = SETUP_CLEANUPS.load(std::sync::atomic::Ordering::SeqCst);

        for point in [
            SetupFaultPoint::AfterSpawn,
            SetupFaultPoint::AfterTreeActivation,
            SetupFaultPoint::BeforeStdoutTake,
            SetupFaultPoint::BeforeStderrTake,
            SetupFaultPoint::BeforeStdinTake,
        ] {
            let marker = tempdir.path().join(format!("setup-fault-{}", point as u8));
            unsafe { std::env::set_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER", &marker) };
            SETUP_FAULT.store(point as u8, std::sync::atomic::Ordering::SeqCst);
            assert!(matches!(
                ContainedChild::spawn(&std::env::current_exe().unwrap(), &args, b"", 1024).await,
                Err(ContainedChildError::Setup(_))
            ));
            SETUP_FAULT.store(0, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(900));
            assert!(
                !marker.exists(),
                "fault {} left an escaping descendant",
                point as u8
            );
        }

        unsafe { std::env::remove_var("NEOTH_TEST_UPDATER_CONTAINED_MARKER") };
        assert_eq!(
            SETUP_CLEANUPS.load(std::sync::atomic::Ordering::SeqCst) - cleanup_start,
            5,
            "each injected post-spawn error used awaited setup cleanup"
        );
    }

    #[tokio::test]
    async fn reader_timeout_aborts_and_awaits_its_task() {
        let (_writer, reader) = tokio::io::duplex(1);
        let task = tokio::spawn(read_capped(reader, 1));
        assert!(matches!(
            join_reader(task, "stdout").await,
            Err(ContainedChildError::WorkerTimedOut { worker: "stdout" })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn checked_kill_failure_is_not_success() {
        let mut group = UnixProcessGroup {
            process_group_id: i32::MIN,
            armed: true,
        };
        assert!(group.terminate().is_err());
        assert!(group.armed, "a failed kill remains armed for Drop retry");
    }
    #[tokio::test]
    async fn native_version_variant_uses_sterile_cwd_and_returns_bounded_stdout_after_reap() {
        let directory = tempfile::tempdir().unwrap();
        let args = vec![OsString::from("--help")];
        let mut child = ContainedChild::spawn_native_cli_version(
            &std::env::current_exe().unwrap(),
            &args,
            directory.path(),
            8 * 1024,
        )
        .await
        .unwrap();
        let output = child
            .wait_until(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.len() <= 8 * 1024);
        assert!(output.stderr.len() <= 8 * 1024);
    }
}
