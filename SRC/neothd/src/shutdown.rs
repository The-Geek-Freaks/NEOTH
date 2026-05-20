//! Cross-platform shutdown signal helper.
//!
//! Daemons call `wait_for_signal()` inside their own task to receive a single
//! event when the operator wants a graceful exit. The daemon owns what
//! happens after — WAL drain, channel adapter teardown, log flush — and
//! returns control to `main` once finished.
//!
//! Unix: SIGTERM, SIGINT, SIGHUP. Windows: Ctrl+C via the console API.
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
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM"),
            _ = sigint.recv() => info!("SIGINT"),
            _ = sighup.recv() => info!("SIGHUP"),
        }
    }
    #[cfg(windows)]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl+C");
    }
}
