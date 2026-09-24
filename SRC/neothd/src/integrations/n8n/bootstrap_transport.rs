//! Bounded, local-only Docker CLI transport for the managed n8n bootstrap.
//!
//! The bootstrap caller owns reconciliation of Docker's remote effect.  This
//! transport only proves that its *local* CLI child was reaped before it
//! returns cancellation or timeout.  It deliberately does not infer that a
//! Docker operation did not reach the daemon.

use std::{ffi::OsString, fmt, io, process::Stdio, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::oneshot,
    task::JoinSet,
};
use zeroize::Zeroizing;

const OUTPUT_LIMIT: usize = 32 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(45);

/// A redacted command outcome.  Do not derive `Debug`: Docker output can
/// contain credentials returned by the in-container bootstrap client.
pub(crate) struct BootstrapCommandOutput {
    pub(crate) succeeded: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: Zeroizing<Vec<u8>>,
    pub(crate) stderr: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for BootstrapCommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapCommandOutput")
            .field("succeeded", &self.succeeded)
            .field("exit_code", &self.exit_code)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

/// Coarse local transport failures.  No variant carries command arguments,
/// stdin, stderr, or a raw OS error because all can contain secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapCommandFailure {
    EmptyCommand,
    Spawn,
    Stdin,
    Capture,
    Wait,
    TimedOut,
    Cancelled,
    OutputLimit,
}

#[async_trait]
pub(crate) trait BootstrapDockerRunner: Send {
    /// Run Docker arguments. `args` may start with the conventional `docker`
    /// program token; it is removed so the real runner always selects its own
    /// local Docker CLI. Sensitive request data belongs exclusively in `stdin`.
    async fn run(
        &mut self,
        args: &[String],
        stdin: Option<Zeroizing<Vec<u8>>>,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Result<BootstrapCommandOutput, BootstrapCommandFailure>;
}

/// Production runner.  Docker endpoint selection is pinned for each process;
/// ambient context selection must never redirect an owner bootstrap.
pub(crate) struct LocalBootstrapDockerRunner {
    program: OsString,
    timeout: Duration,
    pin_local_host: bool,
    #[cfg(test)]
    fixture_env: Option<(OsString, OsString)>,
}

impl Default for LocalBootstrapDockerRunner {
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }
}

impl LocalBootstrapDockerRunner {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            program: OsString::from("docker"),
            timeout,
            pin_local_host: true,
            #[cfg(test)]
            fixture_env: None,
        }
    }

    fn command(
        &self,
        args: &[String],
        has_stdin: bool,
    ) -> Result<Command, BootstrapCommandFailure> {
        let args = match args.first().map(String::as_str) {
            Some("docker") => &args[1..],
            _ => args,
        };
        if args.is_empty() {
            return Err(BootstrapCommandFailure::EmptyCommand);
        }
        let mut command = Command::new(&self.program);
        if self.pin_local_host {
            command.arg("--host").arg(local_docker_host());
        }
        #[cfg(test)]
        if let Some((key, value)) = &self.fixture_env {
            command.env(key, value);
        }
        command
            .args(args)
            .env_remove("DOCKER_HOST")
            .env_remove("DOCKER_CONTEXT")
            .kill_on_drop(true)
            .stdin(if has_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }

    #[cfg(test)]
    fn fixture_runner(program: OsString, timeout: Duration) -> Self {
        Self {
            program,
            timeout,
            // A Rust test binary does not accept Docker's `--host` switch.
            // Production construction cannot disable this pin.
            pin_local_host: false,
            fixture_env: None,
        }
    }

    #[cfg(test)]
    fn fixture_runner_with_env(
        program: OsString,
        timeout: Duration,
        key: OsString,
        value: OsString,
    ) -> Self {
        Self {
            program,
            timeout,
            pin_local_host: false,
            fixture_env: Some((key, value)),
        }
    }
}

#[async_trait]
impl BootstrapDockerRunner for LocalBootstrapDockerRunner {
    async fn run(
        &mut self,
        args: &[String],
        stdin: Option<Zeroizing<Vec<u8>>>,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Result<BootstrapCommandOutput, BootstrapCommandFailure> {
        let mut command = self.command(args, stdin.is_some())?;
        let mut child = command
            .spawn()
            .map_err(|_| BootstrapCommandFailure::Spawn)?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                kill_and_reap(&mut child).await;
                return Err(BootstrapCommandFailure::Capture);
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                kill_and_reap(&mut child).await;
                return Err(BootstrapCommandFailure::Capture);
            }
        };
        let mut captures = JoinSet::new();
        captures.spawn(async move { (true, read_bounded(stdout).await) });
        captures.spawn(async move { (false, read_bounded(stderr).await) });
        let mut stdin_write: Option<
            std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>,
        > = child.stdin.take().zip(stdin).map(|(mut pipe, payload)| {
            Box::pin(async move {
                let result = pipe.write_all(&payload).await;
                if result.is_ok() {
                    pipe.shutdown().await
                } else {
                    result
                }
            })
                as std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>
        });
        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);

        let status = loop {
            tokio::select! {
                biased;
                _ = &mut *cancel => {
                    kill_and_reap(&mut child).await;
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::Cancelled);
                }
                _ = &mut deadline => {
                    kill_and_reap(&mut child).await;
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::TimedOut);
                }
                waited = child.wait() => match waited {
                    Ok(status) => break status,
                    Err(_) => {
                        kill_and_reap(&mut child).await;
                        abort_captures(&mut captures).await;
                        return Err(BootstrapCommandFailure::Wait);
                    }
                },
                write = poll_stdin(&mut stdin_write), if stdin_write.is_some() => {
                    drop(stdin_write.take());
                    if write.is_err() {
                        kill_and_reap(&mut child).await;
                        abort_captures(&mut captures).await;
                        return Err(BootstrapCommandFailure::Stdin);
                    }
                }
            }
        };

        if stdin_write.is_some() {
            tokio::select! {
                _ = &mut *cancel => {
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::Cancelled);
                }
                _ = &mut deadline => {
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::TimedOut);
                }
                write = poll_stdin(&mut stdin_write) => {
                    drop(stdin_write.take());
                    if write.is_err() {
                        abort_captures(&mut captures).await;
                        return Err(BootstrapCommandFailure::Stdin);
                    }
                }
            }
        }

        let mut stdout = None;
        let mut stderr = None;
        while stdout.is_none() || stderr.is_none() {
            tokio::select! {
                _ = &mut *cancel => {
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::Cancelled);
                }
                _ = &mut deadline => {
                    abort_captures(&mut captures).await;
                    return Err(BootstrapCommandFailure::TimedOut);
                }
                completed = captures.join_next() => {
                    let Some(completed) = completed else {
                        return Err(BootstrapCommandFailure::Capture);
                    };
                    let (is_stdout, capture) = match completed {
                        Ok(completed) => completed,
                        Err(_) => {
                            abort_captures(&mut captures).await;
                            return Err(BootstrapCommandFailure::Capture);
                        }
                    };
                    let capture = match capture {
                        Ok(capture) => capture,
                        Err(error) => {
                            abort_captures(&mut captures).await;
                            return Err(error);
                        }
                    };
                    if is_stdout { stdout = Some(capture); } else { stderr = Some(capture); }
                }
            }
        }
        let stdout = stdout.expect("capture loop requires stdout");
        let stderr = stderr.expect("capture loop requires stderr");
        if stdout.overflow || stderr.overflow {
            return Err(BootstrapCommandFailure::OutputLimit);
        }
        Ok(BootstrapCommandOutput {
            succeeded: status.success(),
            exit_code: status.code(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }
}

async fn poll_stdin(
    write: &mut Option<std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>>,
) -> io::Result<()> {
    match write.as_mut() {
        Some(write) => write.await,
        None => std::future::pending().await,
    }
}

async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn abort_captures(captures: &mut JoinSet<(bool, Result<Capture, BootstrapCommandFailure>)>) {
    // Once the child is reaped, retaining any further bytes is pointless and
    // could let a broken pipe task delay cancellation.  Aborting drops the
    // zeroizing capture buffers and closes both inherited pipe handles.
    captures.abort_all();
    while captures.join_next().await.is_some() {}
}

struct Capture {
    bytes: Zeroizing<Vec<u8>>,
    overflow: bool,
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Capture, BootstrapCommandFailure> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(OUTPUT_LIMIT));
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    let mut overflow = false;
    loop {
        let read = reader
            .read(&mut *buffer)
            .await
            .map_err(|_| BootstrapCommandFailure::Capture)?;
        if read == 0 {
            return Ok(Capture { bytes, overflow });
        }
        let remaining = OUTPUT_LIMIT.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        overflow |= retained != read;
    }
}

fn local_docker_host() -> &'static str {
    #[cfg(windows)]
    {
        "npipe:////./pipe/docker_engine"
    }
    #[cfg(not(windows))]
    {
        "unix:///var/run/docker.sock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, path::PathBuf, time::Duration};
    use tokio::io::AsyncWriteExt;

    const FIXTURE_TICK_PATH: &str = "NEOTH_BOOTSTRAP_TRANSPORT_TICK_PATH";
    fn fixture_runner(timeout: Duration) -> LocalBootstrapDockerRunner {
        LocalBootstrapDockerRunner::fixture_runner(
            std::env::current_exe()
                .expect("current test executable")
                .into_os_string(),
            timeout,
        )
    }

    fn fixture_runner_with_tick(
        timeout: Duration,
        tick_path: &std::path::Path,
    ) -> LocalBootstrapDockerRunner {
        LocalBootstrapDockerRunner::fixture_runner_with_env(
            std::env::current_exe()
                .expect("current test executable")
                .into_os_string(),
            timeout,
            OsString::from(FIXTURE_TICK_PATH),
            tick_path.as_os_str().to_os_string(),
        )
    }

    fn fixture_args(name: &str) -> Vec<String> {
        vec![
            "--exact".into(),
            name.into(),
            "--ignored".into(),
            "--nocapture".into(),
        ]
    }

    /// These fixtures only do work when their dedicated test is selected by a
    /// child process.  No mutable environment is shared with parallel tests.
    #[test]
    #[ignore = "child-process fixture"]
    fn fixture_overflow() {
        print!("{}", "x".repeat(OUTPUT_LIMIT + 1));
    }

    #[test]
    #[ignore = "child-process fixture"]
    fn fixture_park() {
        let tick_path = std::env::var_os(FIXTURE_TICK_PATH).map(PathBuf::from);
        for tick in 0..1_000_u32 {
            if let Some(path) = tick_path.as_ref() {
                let _ = std::fs::write(path, format!("{}:{tick}", std::process::id()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "child-process fixture"]
    fn fixture_close_stdin() {
        use std::io::Read as _;

        // Consume one byte first, so the parent write is in flight before this
        // fixture closes its inherited read end. The bounded linger gives the
        // pending write an unambiguous BrokenPipe result before this child exits.
        let mut start = [0_u8; 1];
        std::io::stdin()
            .lock()
            .read_exact(&mut start)
            .expect("fixture receives write start");
        close_fixture_stdin();
        std::thread::sleep(Duration::from_millis(100));
    }

    fn close_fixture_stdin() {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;

            let stdin = std::io::stdin();
            // SAFETY: this child owns its inherited standard-input descriptor.
            assert_eq!(unsafe { libc::close(stdin.as_raw_fd()) }, 0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::Foundation::CloseHandle;

            let stdin = std::io::stdin();
            // SAFETY: this child owns its inherited standard-input pipe handle.
            assert_ne!(unsafe { CloseHandle(stdin.as_raw_handle().cast()) }, 0);
        }
    }

    #[tokio::test]
    async fn bounded_capture_retains_at_most_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(OUTPUT_LIMIT + 2);
        let fixture = vec![b'x'; OUTPUT_LIMIT + 1];
        let write = tokio::spawn(async move { writer.write_all(&fixture).await });
        let captured = read_bounded(reader).await.expect("capture fixture");
        write.await.expect("join writer").expect("write fixture");
        assert_eq!(captured.bytes.len(), OUTPUT_LIMIT);
        assert!(captured.overflow);
    }

    #[tokio::test]
    async fn real_runner_rejects_output_over_the_retained_cap() {
        let (_cancel_tx, mut cancel) = oneshot::channel();
        let result = fixture_runner(Duration::from_secs(5))
            .run(
                &fixture_args("integrations::n8n::bootstrap_transport::tests::fixture_overflow"),
                None,
                &mut cancel,
            )
            .await;
        assert!(matches!(result, Err(BootstrapCommandFailure::OutputLimit)));
    }

    #[tokio::test]
    async fn timeout_stops_the_child_pid_heartbeat_before_returning() {
        let tick_path = std::env::temp_dir().join(format!(
            "neoth-bootstrap-timeout-{}.tick",
            uuid::Uuid::now_v7()
        ));
        let (_cancel_tx, mut cancel) = oneshot::channel();
        let result = fixture_runner_with_tick(Duration::from_secs(5), &tick_path)
            .run(
                &fixture_args("integrations::n8n::bootstrap_transport::tests::fixture_park"),
                None,
                &mut cancel,
            )
            .await;
        assert!(matches!(result, Err(BootstrapCommandFailure::TimedOut)));
        let before = std::fs::read(&tick_path).expect("parked child ticked");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            std::fs::read(&tick_path).expect("tick remains readable"),
            before
        );
        let _ = std::fs::remove_file(tick_path);
    }

    #[tokio::test]
    async fn cancellation_stops_the_child_pid_heartbeat_before_returning() {
        let tick_path = std::env::temp_dir().join(format!(
            "neoth-bootstrap-cancel-{}.tick",
            uuid::Uuid::now_v7()
        ));
        let task_tick_path = tick_path.clone();
        let (send, mut cancel) = oneshot::channel();
        let task = tokio::spawn(async move {
            fixture_runner_with_tick(Duration::from_secs(5), &task_tick_path)
                .run(
                    &fixture_args("integrations::n8n::bootstrap_transport::tests::fixture_park"),
                    None,
                    &mut cancel,
                )
                .await
        });
        let tick_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !tick_path.exists() {
            assert!(
                tokio::time::Instant::now() < tick_deadline,
                "parked child never reported its PID"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = send.send(());
        let result = task.await.expect("join runner");
        assert!(matches!(result, Err(BootstrapCommandFailure::Cancelled)));
        let before = std::fs::read(&tick_path).expect("parked child ticked");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            std::fs::read(&tick_path).expect("tick remains readable"),
            before
        );
        let _ = std::fs::remove_file(tick_path);
    }

    #[tokio::test]
    async fn missing_cli_is_a_coarse_spawn_failure() {
        let (_cancel_tx, mut cancel) = oneshot::channel();
        let missing = PathBuf::from("definitely-not-a-neoth-bootstrap-docker-cli").into_os_string();
        let result = LocalBootstrapDockerRunner::fixture_runner(missing, Duration::from_secs(1))
            .run(&fixture_args("fixture_overflow"), None, &mut cancel)
            .await;
        assert!(matches!(result, Err(BootstrapCommandFailure::Spawn)));
    }

    #[tokio::test]
    async fn closed_stdin_is_a_coarse_failure_without_a_join_panic() {
        let (_cancel_tx, mut cancel) = oneshot::channel();
        let result = fixture_runner(Duration::from_secs(5))
            .run(
                &fixture_args("integrations::n8n::bootstrap_transport::tests::fixture_close_stdin"),
                Some(Zeroizing::new(vec![7_u8; 1024 * 1024])),
                &mut cancel,
            )
            .await;
        assert!(
            matches!(result, Err(BootstrapCommandFailure::Stdin)),
            "closed stdin must be a coarse Stdin failure, got {result:?}"
        );
    }

    #[test]
    fn debug_is_length_only_and_never_exposes_response_bytes() {
        let secret = b"bootstrap-response-secret".to_vec();
        let output = BootstrapCommandOutput {
            succeeded: true,
            exit_code: Some(0),
            stdout: Zeroizing::new(secret.clone()),
            stderr: Zeroizing::new(secret.clone()),
        };
        let debug = format!("{output:?}");
        assert!(!debug.contains("bootstrap-response-secret"));
        assert!(
            !format!("{:?}", BootstrapCommandFailure::Spawn).contains("bootstrap-response-secret")
        );
    }

    #[test]
    fn docker_host_is_compile_target_local() {
        #[cfg(windows)]
        assert_eq!(local_docker_host(), "npipe:////./pipe/docker_engine");
        #[cfg(not(windows))]
        assert_eq!(local_docker_host(), "unix:///var/run/docker.sock");
    }
}
