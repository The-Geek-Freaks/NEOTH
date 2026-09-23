//! GUI-side ownership of the W204 bootstrap wizard session.
//!
//! This deliberately contains no initialization token, marker parsing, or
//! config writer. Those remain daemon-owned (`init::io`) and the existing GUI
//! `finish()` path respectively. The controller only binds a GUI operation to
//! the live daemon boot/session/sequence tuple and refuses to retry a request
//! whose outcome is unknown.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use neothd::daemon::wizard_ipc::WizardIpcClient;
use neothd::wizard::ipc::{
    WizardBootId, WizardIpcMessage, WizardResponse, WizardSequence, WizardSessionId,
    WizardSnapshot, WizardTerminalState,
};
use sha2::{Digest, Sha256};

const BOOTSTRAP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_DISCOVERY_POLL: Duration = Duration::from_millis(50);

// A daemon-loss response is intentionally fail-closed for this GUI lifetime.
// The operation that was in flight may have reached the daemon, so another
// Finish click must not recreate or replay it. A restart opens/resumes the
// daemon's durable pending transaction with a fresh boot binding.
static BOOTSTRAP_START_ATTEMPTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardBinding {
    session_id: WizardSessionId,
    boot_id: WizardBootId,
    accepted_sequence: WizardSequence,
}

impl WizardBinding {
    fn from_snapshot(snapshot: &WizardSnapshot) -> Self {
        Self {
            session_id: snapshot.session_id.clone(),
            boot_id: snapshot.boot_id.clone(),
            accepted_sequence: snapshot.accepted_sequence,
        }
    }

    fn next_sequence(&self) -> Result<WizardSequence> {
        let next = self
            .accepted_sequence
            .0
            .checked_add(1)
            .context("wizard sequence exhausted; refusing to wrap an operator action")?;
        Ok(WizardSequence(next))
    }
}

pub struct WizardSessionController {
    client: WizardIpcClient,
    binding: WizardBinding,
    home: PathBuf,
}

/// A read-only observer deliberately owns a separate discovery/client path.
/// It never borrows the mutation controller while a bounded long-poll is in
/// flight, so operator actions remain available throughout observation.
pub struct WizardWatchHandle {
    home: PathBuf,
    binding: WizardBinding,
}

impl WizardSessionController {
    /// Discover a live bootstrap endpoint or start exactly one bounded child,
    /// then bind to the daemon's authoritative OpenOrResume snapshot.
    pub fn open_or_start(
        home: &Path,
        neothd: &Path,
        spawn_bootstrap: impl FnOnce(&Path, &Path) -> Result<()>,
    ) -> Result<Self> {
        // A sidecar/token is only a discovery hint. It is usable only after
        // OpenOrResume succeeds; an abruptly-dead daemon can leave both files
        // behind. Before any GUI action is accepted, consume the single
        // bootstrap retry to replace that stale endpoint with a new boot.
        match WizardIpcClient::discover(home) {
            Ok(client) => match wizard_runtime()?.block_on(client.open_or_resume()) {
                Ok(response) => Self::bound(home, client, response),
                Err(_) => {
                    if BOOTSTRAP_START_ATTEMPTED.swap(true, Ordering::AcqRel) {
                        bail!(
                            "wizard daemon endpoint did not answer OpenOrResume after its single bootstrap retry"
                        );
                    }
                    spawn_bootstrap(neothd, home)?;
                    let (client, response) = discover_live_after_bootstrap(home)?;
                    Self::bound(home, client, response)
                }
            },
            Err(discovery_error) => {
                if BOOTSTRAP_START_ATTEMPTED.swap(true, Ordering::AcqRel) {
                    return Err(discovery_error).context(
                        "wizard daemon is unavailable after the single bootstrap discovery attempt",
                    );
                }
                spawn_bootstrap(neothd, home)?;
                let (client, response) = discover_live_after_bootstrap(home)?;
                Self::bound(home, client, response)
            }
        }
    }

    fn bound(home: &Path, client: WizardIpcClient, response: WizardResponse) -> Result<Self> {
        let snapshot = accepted_snapshot(response)?;
        Ok(Self {
            client,
            binding: WizardBinding::from_snapshot(&snapshot),
            home: home.to_path_buf(),
        })
    }

    /// Submit only a genuine existing operator selection. The caller passes
    /// the GUI's selection rather than manufacturing daemon progress.
    pub fn submit_operator_choice(&mut self, message: WizardIpcMessage) -> Result<WizardSnapshot> {
        if !message.is_operator_input() {
            bail!("GUI refused to submit daemon-produced wizard status as operator input");
        }
        let response = wizard_runtime()?.block_on(self.client.submit(
            self.binding.session_id.clone(),
            self.binding.boot_id.clone(),
            self.binding.next_sequence()?,
            message,
        ))?;
        self.accept(response)
    }

    /// Commit only the exact prepared freedom.yaml hash. A transport failure
    /// here is intentionally returned as unknown: callers must freeze the UI
    /// rather than retry the same completion action.
    pub fn prepare_for_commit(&mut self, config_sha256: [u8; 32]) -> Result<WizardSnapshot> {
        let response = wizard_runtime()?.block_on(self.client.prepare_for_commit(
            self.binding.session_id.clone(),
            self.binding.boot_id.clone(),
            self.binding.next_sequence()?,
            config_sha256,
        ))?;
        match response {
            WizardResponse::Completed { snapshot } => {
                self.accept(WizardResponse::Completed { snapshot })
            }
            WizardResponse::Rejected { rejection } => {
                bail!("wizard daemon rejected completion: {rejection:?}")
            }
            _ => bail!("wizard daemon did not acknowledge terminal completion"),
        }
    }

    pub fn cancel(
        &mut self,
        from_step: neothd::wizard::ipc::WizardStepId,
    ) -> Result<WizardSnapshot> {
        let response = wizard_runtime()?.block_on(self.client.cancel(
            self.binding.session_id.clone(),
            self.binding.boot_id.clone(),
            self.binding.next_sequence()?,
            from_step,
        ))?;
        let snapshot = self.accept(response)?;
        if snapshot.terminal != WizardTerminalState::Cancelled {
            bail!("wizard daemon did not acknowledge terminal cancellation");
        }
        Ok(snapshot)
    }

    pub fn watch_handle(&self) -> WizardWatchHandle {
        WizardWatchHandle {
            home: self.home.clone(),
            binding: self.binding.clone(),
        }
    }

    /// Incorporate only a non-regressing read-only observation. A concurrent
    /// mutation may have already advanced the cursor; that older watcher
    /// result is benign and must not repaint availability or progress.
    pub fn accept_watch_snapshot(&mut self, snapshot: WizardSnapshot) -> Result<bool> {
        let next = WizardBinding::from_snapshot(&snapshot);
        if next.session_id != self.binding.session_id || next.boot_id != self.binding.boot_id {
            bail!("wizard observer saw a changed boot or session");
        }
        if next.accepted_sequence < self.binding.accepted_sequence {
            return Ok(false);
        }
        self.binding = next;
        Ok(true)
    }

    /// A dropped connection is reconciled only by a fresh OpenOrResume. The
    /// same boot/session may continue; a changed identity is deliberately an
    /// error so no locally queued action can be replayed against a new daemon.
    pub fn reconcile_same_boot(&mut self) -> Result<WizardSnapshot> {
        let client = WizardIpcClient::discover(&self.home)?;
        let response = wizard_runtime()?.block_on(client.open_or_resume())?;
        let snapshot = accepted_snapshot(response)?;
        let next = WizardBinding::from_snapshot(&snapshot);
        if next.session_id != self.binding.session_id || next.boot_id != self.binding.boot_id {
            bail!(
                "wizard daemon boot or session changed; reopen the GUI to reconcile before another action"
            );
        }
        self.client = client;
        self.binding = next;
        Ok(snapshot)
    }

    fn accept(&mut self, response: WizardResponse) -> Result<WizardSnapshot> {
        let snapshot = accepted_snapshot(response)?;
        let next = WizardBinding::from_snapshot(&snapshot);
        if next.session_id != self.binding.session_id || next.boot_id != self.binding.boot_id {
            bail!(
                "wizard daemon changed session or boot; discard local in-flight state and reopen"
            );
        }
        if next.accepted_sequence < self.binding.accepted_sequence {
            bail!("wizard daemon returned a regressed accepted sequence");
        }
        self.binding = next;
        Ok(snapshot)
    }
}

impl WizardWatchHandle {
    pub fn wait_for_change(self) -> Result<WizardSnapshot> {
        let client = WizardIpcClient::discover(&self.home)?;
        let response = wizard_runtime()?.block_on(client.wait_for_change(
            self.binding.session_id.clone(),
            self.binding.boot_id.clone(),
            self.binding.accepted_sequence,
        ))?;
        let snapshot = accepted_snapshot(response)?;
        let next = WizardBinding::from_snapshot(&snapshot);
        if next.session_id != self.binding.session_id || next.boot_id != self.binding.boot_id {
            bail!("wizard observer saw a changed boot or session");
        }
        if next.accepted_sequence < self.binding.accepted_sequence {
            bail!("wizard observer saw a regressed sequence");
        }
        Ok(snapshot)
    }
}

pub fn prepared_config_sha256(path: &Path) -> Result<[u8; 32]> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read prepared config {}", path.display()))?;
    Ok(Sha256::digest(bytes).into())
}

/// Discovery is not success by itself: an abruptly-dead daemon can leave a
/// parseable sidecar and token behind. Keep polling through the one bounded
/// deadline until both discovery *and* OpenOrResume succeed.
fn discover_live_after_bootstrap(home: &Path) -> Result<(WizardIpcClient, WizardResponse)> {
    let deadline = Instant::now() + BOOTSTRAP_DISCOVERY_TIMEOUT;
    loop {
        if let Ok(client) = WizardIpcClient::discover(home)
            && let Ok(response) = wizard_runtime()?.block_on(client.open_or_resume())
        {
            return Ok((client, response));
        }
        if Instant::now() >= deadline {
            bail!("wizard bootstrap sidecar was not discovered before the bounded timeout");
        }
        std::thread::sleep(BOOTSTRAP_DISCOVERY_POLL);
    }
}

fn wizard_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("start GUI wizard IPC runtime")
}

fn accepted_snapshot(response: WizardResponse) -> Result<WizardSnapshot> {
    match response {
        WizardResponse::SessionSnapshot { snapshot }
        | WizardResponse::Progress { snapshot }
        | WizardResponse::CommitReady { snapshot }
        | WizardResponse::Completed { snapshot } => Ok(snapshot),
        WizardResponse::Rejected { rejection } => {
            bail!("wizard daemon rejected request: {rejection:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_config_hash_is_stable_and_content_bound() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("freedom.yaml");
        std::fs::write(&config, "operator_id: sam\n").unwrap();
        let first = prepared_config_sha256(&config).unwrap();
        assert_eq!(first, prepared_config_sha256(&config).unwrap());
        std::fs::write(&config, "operator_id: alex\n").unwrap();
        assert_ne!(first, prepared_config_sha256(&config).unwrap());
    }

    #[test]
    fn binding_uses_exact_next_sequence_and_never_wraps() {
        let binding = WizardBinding {
            session_id: WizardSessionId("session".into()),
            boot_id: WizardBootId("boot".into()),
            accepted_sequence: WizardSequence(41),
        };
        assert_eq!(binding.next_sequence().unwrap(), WizardSequence(42));
        let exhausted = WizardBinding {
            accepted_sequence: WizardSequence(u64::MAX),
            ..binding
        };
        assert!(exhausted.next_sequence().is_err());
    }

    /// Hosted/private-IPC regression over the real GUI controller. The server
    /// has a separate runtime thread; `WizardWatchHandle::wait_for_change()`
    /// must not borrow the mutable controller while an operator selection is
    /// admitted. This is intentionally not run during the BSOD hold.
    #[cfg(any(unix, windows))]
    #[test]
    fn private_server_controller_observer_and_mutation_progress_concurrently() {
        use neothd::daemon::wizard_ipc::bind_and_serve;
        use neothd::wizard::recommend::ChannelRecommendation;
        use std::sync::mpsc;

        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().to_path_buf();
        let (ready_send, ready_recv) = mpsc::sync_channel(1);
        let (stop_send, stop_recv) = mpsc::sync_channel(1);
        let server_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (server, guard) = bind_and_serve(&home_path).unwrap();
                ready_send.send(()).unwrap();
                loop {
                    if stop_recv.try_recv().is_ok() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                guard.stop();
                let _ = server.await;
            });
        });
        ready_recv
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();

        let mut controller = WizardSessionController::open_or_start(
            home.path(),
            Path::new("unused-neothd"),
            |_, _| anyhow::bail!("existing private server must be discovered"),
        )
        .unwrap();
        let initial = controller.watch_handle();
        let observer = std::thread::spawn(move || initial.wait_for_change());
        let mutation = controller
            .submit_operator_choice(WizardIpcMessage::ChannelOverride {
                channel: ChannelRecommendation::Cli,
            })
            .unwrap();
        let observed = observer.join().unwrap().unwrap();
        assert!(observed.accepted_sequence >= mutation.accepted_sequence);
        assert!(controller.accept_watch_snapshot(observed).unwrap());

        // This emulates a late watcher response captured before the mutation.
        // It must not replace the controller's newer cursor or repaint status.
        let stale = WizardSnapshot {
            accepted_sequence: WizardSequence(0),
            ..mutation
        };
        assert!(!controller.accept_watch_snapshot(stale).unwrap());
        stop_send.send(()).unwrap();
        server_thread.join().unwrap();
    }
}
