//! Shared CLI version-probe helper (GOLD-ARCH-14, origin D-35).
//!
//! Probes use Windows `cmd /C` for npm shims and retain only bounded stdout
//! and stderr. A timeout or output overflow kills and reaps the direct child.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

const MAX_VERSION_STDOUT_BYTES: usize = 8 * 1024;
const MAX_VERSION_STDERR_BYTES: usize = 8 * 1024;
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The capture readers are spawned so stdout and stderr cannot deadlock each
/// other. Keeping both handles in this owner makes cancellation scoped: Drop
/// aborts either reader instead of detaching it after the probe future exits.
struct OwnedCaptureTasks {
    stdout: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
}

enum CaptureAwait {
    Completed(Option<Vec<u8>>),
    Pending,
}

impl OwnedCaptureTasks {
    fn spawn(
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
        overflow: Arc<AtomicBool>,
    ) -> Self {
        Self {
            stdout: Some(tokio::spawn(capture_bounded(
                stdout,
                MAX_VERSION_STDOUT_BYTES,
                Arc::clone(&overflow),
            ))),
            stderr: Some(tokio::spawn(capture_bounded(
                stderr,
                MAX_VERSION_STDERR_BYTES,
                overflow,
            ))),
        }
    }

    async fn abort_and_join(&mut self) {
        if let Some(task) = self.stdout.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.stderr.take() {
            task.abort();
            let _ = task.await;
        }
    }

    async fn join_bounded(
        &mut self,
        timeout: Option<Duration>,
        started: Instant,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let stdout = match self.join_one(true, timeout, started).await {
            Some(stdout) => stdout,
            None => {
                self.abort_and_join().await;
                return None;
            }
        };
        let stderr = match self.join_one(false, timeout, started).await {
            Some(stderr) => stderr,
            None => {
                self.abort_and_join().await;
                return None;
            }
        };
        Some((stdout, stderr))
    }

    async fn join_one(
        &mut self,
        stdout: bool,
        timeout: Option<Duration>,
        started: Instant,
    ) -> Option<Vec<u8>> {
        let task = if stdout {
            self.stdout.as_mut()?
        } else {
            self.stderr.as_mut()?
        };
        let output = await_capture(task, timeout, started).await;
        match output {
            CaptureAwait::Completed(output) => {
                if stdout {
                    let _ = self.stdout.take();
                } else {
                    let _ = self.stderr.take();
                }
                output
            }
            CaptureAwait::Pending => None,
        }
    }
}

impl Drop for OwnedCaptureTasks {
    fn drop(&mut self) {
        if let Some(task) = &self.stdout {
            task.abort();
        }
        if let Some(task) = &self.stderr {
            task.abort();
        }
    }
}

/// Probe `<binary> <args...>` and return bounded, trimmed stdout on success.
///
/// On Windows the call is wrapped through `cmd /C` so npm shell-script shims
/// resolve like real executables. A supplied timeout caps the whole child and
/// capture lifetime. Spawn failure, non-zero exit, timeout, output overflow,
/// non-UTF-8 output, and empty output all return `None`.
pub async fn cli_version_args(
    binary: &str,
    args: &[&str],
    timeout: Option<Duration>,
) -> Option<String> {
    cli_version_args_with_env(binary, args, timeout, &[]).await
}

/// Build the bounded version-probe command used by every caller. The supplied
/// environment applies only to this child and never changes process state.
pub(crate) fn cli_version_command(
    binary: &str,
    args: &[&str],
    environment: &[(&str, &str)],
) -> Command {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(binary).args(args);
        c
    } else {
        let mut c = Command::new(binary);
        c.args(args);
        c
    };
    for (key, value) in environment {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Bounded version probe with a caller-scoped child environment. The child is
/// killed on future cancellation; timeout and overflow explicitly kill and
/// reap the direct child before returning.
pub(crate) async fn cli_version_args_with_env(
    binary: &str,
    args: &[&str],
    timeout: Option<Duration>,
    environment: &[(&str, &str)],
) -> Option<String> {
    cli_version_command_bounded(cli_version_command(binary, args, environment), timeout).await
}

async fn cli_version_command_bounded(
    command: Command,
    timeout: Option<Duration>,
) -> Option<String> {
    cli_version_command_bounded_with_capture(command, timeout, OwnedCaptureTasks::spawn, || {})
        .await
}

async fn cli_version_command_bounded_with_capture<C, H>(
    mut command: Command,
    timeout: Option<Duration>,
    capture: C,
    before_join: H,
) -> Option<String>
where
    C: FnOnce(
        tokio::process::ChildStdout,
        tokio::process::ChildStderr,
        Arc<AtomicBool>,
    ) -> OwnedCaptureTasks,
    H: FnOnce(),
{
    command.kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_and_reap(&mut child).await;
            return None;
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_and_reap(&mut child).await;
            return None;
        }
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let mut captures = capture(stdout, stderr, Arc::clone(&overflow));
    let started = Instant::now();
    let mut timed_out = false;
    let mut poll_failed = false;
    let status = loop {
        if overflow.load(Ordering::Acquire) {
            terminate_and_reap(&mut child).await;
            break None;
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            timed_out = true;
            terminate_and_reap(&mut child).await;
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => tokio::time::sleep(PROBE_POLL_INTERVAL).await,
            Err(_) => {
                poll_failed = true;
                terminate_and_reap(&mut child).await;
                break None;
            }
        }
    };

    if timed_out || poll_failed || overflow.load(Ordering::Acquire) {
        captures.abort_and_join().await;
        return None;
    }

    before_join();
    let (stdout, _stderr) = captures.join_bounded(timeout, started).await?;
    if overflow.load(Ordering::Acquire) || !status?.success() {
        return None;
    }
    String::from_utf8(stdout).ok().and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

/// The direct child has no reusable process-group authority. In particular,
/// Windows `cmd /C` descendants are not claimed to be tree-killed here.
async fn terminate_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn await_capture(
    task: &mut tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    timeout: Option<Duration>,
    started: Instant,
) -> CaptureAwait {
    let joined = match timeout {
        Some(limit) => {
            let Some(remaining) = limit.checked_sub(started.elapsed()) else {
                return CaptureAwait::Pending;
            };
            match tokio::time::timeout(remaining, &mut *task).await {
                Ok(result) => result,
                Err(_) => return CaptureAwait::Pending,
            }
        }
        None => task.await,
    };
    CaptureAwait::Completed(joined.ok().and_then(Result::ok))
}

/// Drain one pipe without retaining more than its cap. Continuing to drain
/// after overflow lets the direct child observe its kill instead of blocking
/// on a full pipe.
async fn capture_bounded<R>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut retained = Vec::with_capacity(limit.min(1024));
    let mut buffer = [0u8; 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(retained);
        }
        let room = limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(room)]);
        if count > room {
            overflow.store(true, Ordering::Release);
        }
    }
}

/// Convenience: `<binary> --version`, 5s cap.
pub async fn cli_version(binary: &str) -> Option<String> {
    cli_version_args(binary, &["--version"], Some(Duration::from_secs(5))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const CHILD_MODE: &str = "NEOTH_VERSION_PROBE_TEST_CHILD_MODE";

    struct DropSignal(Arc<AtomicBool>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn bounded_probe_test_child() {
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return;
        };
        match mode.as_str() {
            "normal" => {
                let mut out = std::io::stdout().lock();
                writeln!(out, "fixture-version 1.0").unwrap();
            }
            "overflow" => {
                let mut out = std::io::stdout().lock();
                out.write_all(&vec![b'x'; MAX_VERSION_STDOUT_BYTES + 1])
                    .unwrap();
            }
            "timeout" => std::thread::sleep(Duration::from_secs(1)),
            "environment" => {
                let mut out = std::io::stdout().lock();
                writeln!(
                    out,
                    "{}",
                    std::env::var("OCR_NO_UPDATE").unwrap_or_else(|_| "<unset>".into())
                )
                .unwrap();
            }
            _ => std::process::exit(2),
        }
    }

    fn test_child(mode: &str, environment: &[(&str, &str)]) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("installers::probe::tests::bounded_probe_test_child")
            .arg("--nocapture")
            .env(CHILD_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.env_remove("OCR_NO_UPDATE");
        for (key, value) in environment {
            command.env(key, value);
        }
        command
    }

    async fn paused_capture<R>(
        reader: R,
        limit: usize,
        overflow: Arc<AtomicBool>,
        pause: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    ) -> std::io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let _signal = DropSignal(dropped);
        pause.notified().await;
        capture_bounded(reader, limit, overflow).await
    }

    #[tokio::test]
    async fn injected_child_normal_overflow_and_timeout_are_bounded() {
        let normal =
            cli_version_command_bounded(test_child("normal", &[]), Some(Duration::from_secs(1)))
                .await
                .expect("normal fixture output");
        assert!(normal.contains("fixture-version 1.0"));
        assert!(
            cli_version_command_bounded(test_child("overflow", &[]), Some(Duration::from_secs(1)),)
                .await
                .is_none()
        );
        assert!(
            cli_version_command_bounded(
                test_child("timeout", &[]),
                Some(Duration::from_millis(25)),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn injected_child_environment_is_scoped_and_ordinary_probe_is_unset() {
        let ordinary_command = cli_version_command("ocr", &["--version"], &[]);
        assert!(
            ordinary_command
                .as_std()
                .get_envs()
                .all(|(key, _)| key != std::ffi::OsStr::new("OCR_NO_UPDATE"))
        );
        let impact = cli_version_command_bounded(
            test_child("environment", &[("OCR_NO_UPDATE", "1")]),
            Some(Duration::from_secs(1)),
        )
        .await
        .expect("impact environment fixture");
        assert!(impact.contains("1"));
        let ordinary = cli_version_command_bounded(
            test_child("environment", &[]),
            Some(Duration::from_secs(1)),
        )
        .await
        .expect("ordinary environment fixture");
        assert!(ordinary.contains("<unset>"));
    }

    #[tokio::test]
    async fn real_core_cancellation_drops_paused_capture_readers() {
        let stdout_dropped = Arc::new(AtomicBool::new(false));
        let stderr_dropped = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(tokio::sync::Notify::new());
        let joined = Arc::new(tokio::sync::Notify::new());
        let outer_stdout = Arc::clone(&stdout_dropped);
        let outer_stderr = Arc::clone(&stderr_dropped);
        let outer_pause = Arc::clone(&pause);
        let outer_joined = Arc::clone(&joined);
        let outer = tokio::spawn(async move {
            cli_version_command_bounded_with_capture(
                test_child("normal", &[]),
                Some(Duration::from_secs(1)),
                move |stdout, stderr, overflow| OwnedCaptureTasks {
                    stdout: Some(tokio::spawn(paused_capture(
                        stdout,
                        MAX_VERSION_STDOUT_BYTES,
                        Arc::clone(&overflow),
                        Arc::clone(&outer_pause),
                        outer_stdout,
                    ))),
                    stderr: Some(tokio::spawn(paused_capture(
                        stderr,
                        MAX_VERSION_STDERR_BYTES,
                        overflow,
                        outer_pause,
                        outer_stderr,
                    ))),
                },
                move || outer_joined.notify_one(),
            )
            .await
        });
        joined.notified().await;
        outer.abort();
        let _ = outer.await;
        for _ in 0..8 {
            if stdout_dropped.load(Ordering::Acquire) && stderr_dropped.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(stdout_dropped.load(Ordering::Acquire));
        assert!(stderr_dropped.load(Ordering::Acquire));
    }
}
