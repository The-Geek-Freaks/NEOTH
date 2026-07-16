//! Cross-platform shutdown signal helper.
//!
//! Daemons call `wait_for_signal()` inside their own task to receive a single
//! event when the operator wants a graceful exit. The daemon owns what
//! happens after — WAL drain, channel adapter teardown, log flush — and
//! returns control to `main` once finished.
//!
//! Unix: SIGTERM and SIGINT. Windows: Ctrl+C via the console API. SIGHUP is
//! explicitly consumed but does not terminate the daemon: logrotate and process
//! supervisors use it for reload/reopen semantics, while NEOTH reloads through
//! its cross-platform filesystem sentinel. Registering the handler matters —
//! merely omitting SIGHUP would leave Unix's default abrupt-termination action.
//! Hard kills (SIGKILL, `taskkill /F`) bypass this entirely; recovery on
//! next startup is handled by WAL CRC verification.

use tracing::info;

/// Await any of the shutdown signals defined for the current OS.
/// Returns once one fires; ignores subsequent signals.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut sighup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("SIGTERM");
                    break;
                },
                _ = sigint.recv() => {
                    info!("SIGINT");
                    break;
                },
                _ = sighup.recv() => info!("SIGHUP ignored; use `neoth reload` for config reload"),
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl+C");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::{Duration, Instant};

    #[test]
    fn signal_child_process() {
        let Some(ready) = std::env::var_os("NEOTH_SIGNAL_CHILD_READY") else {
            return;
        };
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let waiter = tokio::spawn(super::wait_for_signal());
            tokio::task::yield_now().await;
            std::fs::write(ready, b"ready").unwrap();
            waiter.await.unwrap();
        });
    }

    #[test]
    fn sighup_is_consumed_but_sigterm_exits_cleanly() {
        let home = tempfile::tempdir().unwrap();
        let ready = home.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shutdown::tests::signal_child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NEOTH_SIGNAL_CHILD_READY", &ready)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        let started = Instant::now();
        while !ready.exists() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "signal-test child did not become ready");

        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        // SAFETY: the pid belongs to the child above; signals 1 and 15 are
        // SIGHUP/SIGTERM on every supported Unix target.
        assert_eq!(unsafe { kill(child.id() as i32, 1) }, 0);
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            child.try_wait().unwrap().is_none(),
            "SIGHUP must not terminate the daemon"
        );

        assert_eq!(unsafe { kill(child.id() as i32, 15) }, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "SIGTERM child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
    }
}
