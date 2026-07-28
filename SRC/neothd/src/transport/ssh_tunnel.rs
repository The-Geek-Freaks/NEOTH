//! TERMIX-01 — SSH local-port-forward tunnel (feature `ssh-tunnel`).
//!
//! The `russh` client [`Handler`] enforces host-key TOFU via
//! [`super::ssh_tofu::TofuStore`]. The supervisor owns every forwarding task,
//! bounds peer-controlled operations, and reconnects without rebinding the
//! local listener.
//!
//! Crypto: `russh` is pulled with the `ring` backend (NOT aws-lc-rs) so it
//! builds on Windows MSVC with no cmake/nasm.

use std::borrow::Cow;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client;
use russh::keys::ssh_key;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};

// Config types live unconditionally in `ssh_config` (so freedom.yaml
// round-trips on slim builds); re-exported here so runtime callers keep
// the natural `ssh_tunnel::SshTunnelConfig` path.
pub use super::ssh_config::{SshAuth, SshEndpoint, SshTunnelConfig};
use super::ssh_tofu::{TofuOutcome, TofuStore};

pub(super) const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const SSH_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const SSH_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const SSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SSH_SESSION_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const SSH_STABLE_SESSION_WINDOW: Duration = Duration::from_secs(30);
const SSH_MAX_JUMP_CHAIN_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const SSH_MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const SSH_MAX_BLOCKING_KEY_LOADERS: usize = 2;
pub(super) const MAX_CONCURRENT_FORWARDS: usize = 64;
#[cfg(test)]
const INSECURE_TEST_PASSWORD_PREFIX: &str = "neoth-insecure-test-fixture:";

#[derive(Debug)]
struct FatalSshConfigurationError(String);

impl fmt::Display for FatalSshConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FatalSshConfigurationError {}

fn fatal_ssh_configuration(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(FatalSshConfigurationError(format!("{error:#}")))
}

pub(super) fn is_fatal_ssh_configuration(error: &anyhow::Error) -> bool {
    error.downcast_ref::<FatalSshConfigurationError>().is_some()
}

fn rejected_password_authentication(endpoint: &SshEndpoint) -> Option<anyhow::Error> {
    let SshAuth::Password(_password) = &endpoint.auth else {
        return None;
    };

    #[cfg(test)]
    if _password
        .expose_secret()
        .starts_with(INSECURE_TEST_PASSWORD_PREFIX)
    {
        // `russh` password authentication is retained only for hermetic test
        // fixtures. Production builds do not compile the upstream call.
        return None;
    }

    Some(fatal_ssh_configuration(anyhow!(
        "SSH password authentication is disabled for {}@{} because the current \
         russh transport can retain and debug-log password payloads; configure \
         auth: private_key until NEOTH adopts a patched upstream",
        endpoint.username,
        endpoint.host_key()
    )))
}

fn key_loader_limiter() -> Arc<Semaphore> {
    static LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(LIMITER.get_or_init(|| Arc::new(Semaphore::new(SSH_MAX_BLOCKING_KEY_LOADERS))))
}

/// Whether a TOFU outcome lets the SSH handshake proceed: a first sight or an
/// exact re-sight proceeds; a CHANGED host key is refused (possible MITM).
pub fn tofu_allows(outcome: &TofuOutcome) -> bool {
    matches!(outcome, TofuOutcome::Accepted | TofuOutcome::Matched)
}

/// `russh` client handler enforcing host-key TOFU. One per SSH session; the
/// `host_key` is the `"host:port"` the session is dialing.
pub struct SshHandler {
    tofu: Arc<Mutex<TofuStore>>,
    host_key: String,
}

impl SshHandler {
    pub fn new(tofu: Arc<Mutex<TofuStore>>, host_key: String) -> Self {
        Self { tofu, host_key }
    }
}

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let algo = server_public_key.algorithm().to_string();
        // The OpenSSH textual form (algo + base64) is a stable host-key identity.
        let repr = server_public_key
            .to_openssh()
            .map_err(|e| anyhow!("encode server host key: {e}"))?;
        let tofu = Arc::clone(&self.tofu);
        let host_key = self.host_key.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            tofu.blocking_lock()
                .check_and_update(&host_key, &algo, repr.as_bytes())
        })
        .await
        .map_err(|error| anyhow!("SSH TOFU verifier task failed: {error}"))??;
        let allow = tofu_allows(&outcome);
        if !allow {
            tracing::error!(
                host = %self.host_key,
                "SSH host key CHANGED — refusing connection (possible MITM); resolve via the TOFU store",
            );
        }
        Ok(allow)
    }
}

/// Establish an SSH session to `endpoint`, enforcing TOFU + authenticating.
/// Used by the tunnel + jump-chain. Returns the live client handle.
pub async fn connect_endpoint(
    endpoint: &SshEndpoint,
    tofu: Arc<Mutex<TofuStore>>,
    config: Arc<client::Config>,
) -> Result<client::Handle<SshHandler>> {
    connect_endpoint_with_timeouts(
        endpoint,
        tofu,
        config,
        SSH_CONNECT_TIMEOUT,
        SSH_AUTH_TIMEOUT,
    )
    .await
}

pub(super) async fn connect_endpoint_with_timeouts(
    endpoint: &SshEndpoint,
    tofu: Arc<Mutex<TofuStore>>,
    config: Arc<client::Config>,
    connect_timeout: Duration,
    auth_timeout: Duration,
) -> Result<client::Handle<SshHandler>> {
    let handler = SshHandler::new(tofu, endpoint.host_key());
    let mut handle = timeout(
        connect_timeout,
        client::connect(config, (endpoint.host.as_str(), endpoint.port), handler),
    )
    .await
    .with_context(|| {
        format!(
            "SSH connect/handshake timed out after {connect_timeout:?} for {}",
            endpoint.host_key()
        )
    })??;
    authenticate_with_timeout(&mut handle, endpoint, auth_timeout).await?;
    Ok(handle)
}

/// Authenticate an already-connected handle for `endpoint`.
pub async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    endpoint: &SshEndpoint,
) -> Result<()> {
    authenticate_with_timeout(handle, endpoint, SSH_AUTH_TIMEOUT).await
}

pub(super) async fn authenticate_with_timeout(
    handle: &mut client::Handle<SshHandler>,
    endpoint: &SshEndpoint,
    auth_timeout: Duration,
) -> Result<()> {
    let ok = match &endpoint.auth {
        SshAuth::Password(password) => {
            if let Some(error) = rejected_password_authentication(endpoint) {
                return Err(error);
            }

            #[cfg(test)]
            {
                timeout(
                    auth_timeout,
                    handle
                        .authenticate_password(endpoint.username.clone(), password.expose_secret()),
                )
                .await
                .with_context(|| {
                    format!(
                        "SSH test-fixture password authentication timed out after \
                         {auth_timeout:?} for {}@{}",
                        endpoint.username,
                        endpoint.host_key()
                    )
                })??
                .success()
            }

            #[cfg(not(test))]
            {
                let _ = (handle, password, auth_timeout);
                return Err(
                    rejected_password_authentication(endpoint).unwrap_or_else(|| {
                        fatal_ssh_configuration(anyhow!(
                            "SSH password authentication reached an invalid production state"
                        ))
                    }),
                );
            }
        }
        SshAuth::PrivateKey { path, passphrase } => {
            // File I/O and encrypted-key KDF work are blocking. Keep both off
            // Tokio workers and charge them against the SAME deadline as the
            // subsequent network authentication; otherwise key loading could
            // bypass (or double) the advertised authentication timeout.
            let deadline = Instant::now() + auth_timeout;
            let timeout_error = format!(
                "SSH public-key authentication timed out after {auth_timeout:?} for {}@{}",
                endpoint.username,
                endpoint.host_key()
            );
            let key = load_private_key_before_deadline(
                deadline,
                path.clone(),
                passphrase.clone(),
                timeout_error.clone(),
            )
            .await
            .map_err(fatal_ssh_configuration)?;
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            timeout_at(
                deadline,
                handle.authenticate_publickey(endpoint.username.clone(), key),
            )
            .await
            .map_err(|_| anyhow!(timeout_error))??
            .success()
        }
    };
    if ok {
        Ok(())
    } else {
        Err(anyhow!(
            "SSH authentication failed for {}@{}",
            endpoint.username,
            endpoint.host_key()
        ))
    }
}

async fn load_private_key_before_deadline(
    deadline: Instant,
    path: PathBuf,
    passphrase: Option<crate::secret::SecretString>,
    timeout_error: String,
) -> Result<ssh_key::PrivateKey> {
    let error_path = path.clone();
    run_blocking_before_deadline(
        key_loader_limiter(),
        deadline,
        "SSH private-key loader",
        timeout_error,
        move || {
            let metadata = std::fs::metadata(&path)
                .map_err(|error| anyhow!("inspect SSH key {}: {error}", path.display()))?;
            if !metadata.is_file() {
                return Err(anyhow!(
                    "SSH private key is not a regular file: {}",
                    path.display()
                ));
            }
            if metadata.len() > SSH_MAX_PRIVATE_KEY_BYTES {
                return Err(anyhow!(
                    "SSH private key {} exceeds the {} byte limit",
                    path.display(),
                    SSH_MAX_PRIVATE_KEY_BYTES
                ));
            }
            russh::keys::load_secret_key(
                &path,
                passphrase.as_ref().map(|secret| secret.expose_secret()),
            )
            .map_err(|error| anyhow!("load SSH key {}: {error}", path.display()))
        },
    )
    .await
    .with_context(|| format!("load SSH key {}", error_path.display()))
}

async fn run_blocking_before_deadline<T, F>(
    limiter: Arc<Semaphore>,
    deadline: Instant,
    operation: &'static str,
    timeout_error: String,
    task: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let permit = timeout_at(deadline, limiter.acquire_owned())
        .await
        .map_err(|_| anyhow!(timeout_error.clone()))?
        .map_err(|_| anyhow!("{operation} limiter closed"))?;
    timeout_at(
        deadline,
        tokio::task::spawn_blocking(move || {
            // A blocking task cannot be force-cancelled. Keeping the owned
            // permit inside it preserves the hard global cap even if the
            // caller's deadline expires while filesystem/KDF work continues.
            let _permit = permit;
            task()
        }),
    )
    .await
    .map_err(|_| anyhow!(timeout_error))?
    .map_err(|error| anyhow!("{operation} task failed: {error}"))?
}

/// Exponential reconnect backoff for tunnel connect attempt `n` (0-based),
/// `base · 2^n` capped at `base · 2^6` (the shift saturates at 6). Pure +
/// testable; the live connect/retry loop calls it between failed attempts.
pub fn reconnect_delay(base: Duration, attempt: u32) -> Duration {
    base.saturating_mul(1u32 << attempt.min(6))
}

/// A running local-forward tunnel. `shutdown` (or drop) aborts the background
/// connect/forward task.
pub struct SshTunnel {
    local_port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl SshTunnel {
    /// The bound local port (resolved even when the config asked for `0`).
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    #[cfg(test)]
    pub(super) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Abort the tunnel's background task.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind the local listener and spawn the connect → retry → forward loop. Returns
/// once the local port is bound (so `local_port()` is immediately usable); the
/// SSH connect proceeds in the background with exponential-backoff retry.
pub async fn spawn_tunnel(cfg: SshTunnelConfig, tofu: Arc<Mutex<TofuStore>>) -> Result<SshTunnel> {
    for endpoint in cfg.jump_hosts.iter().chain(std::iter::once(&cfg.endpoint)) {
        if let Some(error) = rejected_password_authentication(endpoint) {
            return Err(error);
        }
    }

    let listener = TcpListener::bind(("127.0.0.1", cfg.local_port)).await?;
    let local_port = listener.local_addr()?.port();
    let config = hardened_client_config();
    let task = tokio::spawn(run_forward(listener, cfg, tofu, config));
    Ok(SshTunnel { local_port, task })
}

fn hardened_client_config() -> Arc<client::Config> {
    let mut config = client::Config::default();
    config.preferred.compression = Cow::Owned(vec![russh::compression::NONE]);
    config.keepalive_interval = Some(SSH_KEEPALIVE_INTERVAL);
    config.keepalive_max = 3;
    config.inactivity_timeout = Some(SSH_INACTIVITY_TIMEOUT);
    config.nodelay = true;
    Arc::new(config)
}

fn jump_chain_timeout(jump_hosts: usize) -> Duration {
    let endpoints = u32::try_from(jump_hosts.saturating_add(1)).unwrap_or(u32::MAX);
    SSH_CONNECT_TIMEOUT
        .saturating_add(SSH_AUTH_TIMEOUT)
        .saturating_mul(endpoints)
        .min(SSH_MAX_JUMP_CHAIN_TIMEOUT)
}

enum ForwardOutcome {
    Complete,
    Reconnect(anyhow::Error),
}

/// The connect/retry/forward driver. Reconnects (jump-aware) on transport loss
/// until `max_retries` consecutive connect or unstable-session failures, then
/// gives up. A session must survive [`SSH_STABLE_SESSION_WINDOW`] before it
/// resets that failure streak.
async fn run_forward(
    listener: TcpListener,
    cfg: SshTunnelConfig,
    tofu: Arc<Mutex<TofuStore>>,
    config: Arc<client::Config>,
) {
    let mut attempt = 0u32;
    loop {
        let chain_timeout = jump_chain_timeout(cfg.jump_hosts.len());
        let connection = timeout(
            chain_timeout,
            super::ssh_jump::connect_via_jumps(
                &cfg.jump_hosts,
                &cfg.endpoint,
                tofu.clone(),
                config.clone(),
            ),
        )
        .await
        .with_context(|| {
            format!(
                "SSH jump chain timed out after {chain_timeout:?} for {}",
                cfg.endpoint.host_key()
            )
        })
        .and_then(|result| result);
        let handle = match connection {
            Ok(h) => {
                tracing::info!(host = %cfg.endpoint.host_key(), local_port = local_port_of(&listener), "ssh tunnel connected");
                Arc::new(h)
            }
            Err(e) => {
                if is_fatal_ssh_configuration(&e) {
                    tracing::error!(
                        error = %e,
                        host = %cfg.endpoint.host_key(),
                        "ssh tunnel has a fatal SSH configuration error — refusing to retry"
                    );
                    return;
                }
                if attempt >= cfg.max_retries {
                    tracing::error!(error = %e, host = %cfg.endpoint.host_key(), "ssh tunnel: max retries reached — giving up");
                    return;
                }
                let delay = reconnect_delay(cfg.retry_delay, attempt);
                tracing::warn!(error = %e, attempt, retry_in_secs = delay.as_secs(), "ssh tunnel connect failed — retrying");
                attempt += 1;
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        // Every per-connection task belongs to this session. Dropping or
        // aborting the root task drops this JoinSet and therefore aborts all
        // children; reconnect also explicitly drains them before replacing the
        // handle. No forwarding task is detached from its tunnel.
        let mut forwards = JoinSet::new();
        let liveness_handle = Arc::clone(&handle);
        let session_closed = wait_for_session_close(liveness_handle);
        tokio::pin!(session_closed);
        let stable_session = tokio::time::sleep(SSH_STABLE_SESSION_WINDOW);
        tokio::pin!(stable_session);
        let mut session_is_stable = false;
        let reconnect_reason = loop {
            tokio::select! {
                accepted = listener.accept(), if has_forward_capacity(forwards.len()) => {
                    let (local, _peer) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::error!(error = %error, "ssh tunnel: local listener failed");
                            forwards.shutdown().await;
                            return;
                        }
                    };
                    let session = Arc::clone(&handle);
                    let remote_host = cfg.remote_host.clone();
                    let remote_port = cfg.remote_port;
                    forwards.spawn(forward_connection(
                        local,
                        session,
                        remote_host,
                        remote_port,
                    ));
                }
                completed = forwards.join_next(), if !forwards.is_empty() => {
                    match completed {
                        Some(Ok(ForwardOutcome::Complete)) => {}
                        Some(Ok(ForwardOutcome::Reconnect(error))) => break error,
                        Some(Err(error)) if error.is_cancelled() => {}
                        Some(Err(error)) => {
                            break anyhow!("SSH forwarding task failed: {error}");
                        }
                        None => {}
                    }
                }
                () = &mut session_closed => {
                    break anyhow!("SSH session closed");
                }
                () = &mut stable_session, if !session_is_stable => {
                    attempt = 0;
                    session_is_stable = true;
                    tracing::debug!(
                        host = %cfg.endpoint.host_key(),
                        stable_secs = SSH_STABLE_SESSION_WINDOW.as_secs(),
                        "SSH session reached the stability window; retry streak reset"
                    );
                }
            }
        };

        forwards.shutdown().await;
        drop(handle);
        if attempt >= cfg.max_retries {
            tracing::error!(
                error = %reconnect_reason,
                host = %cfg.endpoint.host_key(),
                "ssh tunnel: max retries reached after unstable session loss — giving up"
            );
            return;
        }
        let delay = reconnect_delay(cfg.retry_delay, attempt);
        tracing::warn!(
            error = %reconnect_reason,
            attempt,
            retry_in_secs = delay.as_secs(),
            "ssh tunnel session lost — retrying with backoff"
        );
        attempt += 1;
        tokio::time::sleep(delay).await;
    }
}

async fn wait_for_session_close(handle: Arc<client::Handle<SshHandler>>) {
    while !handle.is_closed() {
        tokio::time::sleep(SSH_SESSION_HEALTH_INTERVAL).await;
    }
}

fn has_forward_capacity(active: usize) -> bool {
    active < MAX_CONCURRENT_FORWARDS
}

async fn forward_connection(
    mut local: tokio::net::TcpStream,
    handle: Arc<client::Handle<SshHandler>>,
    remote_host: String,
    remote_port: u16,
) -> ForwardOutcome {
    let channel = match timeout(
        SSH_CHANNEL_OPEN_TIMEOUT,
        handle.channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1", 0),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        Ok(Err(error)) => {
            if handle.is_closed() {
                return ForwardOutcome::Reconnect(anyhow!(
                    "opening SSH direct-tcpip channel failed on a closed session: {error}"
                ));
            }
            tracing::warn!(
                error = %error,
                "SSH direct-tcpip channel was rejected; keeping the healthy session"
            );
            return ForwardOutcome::Complete;
        }
        Err(_) => {
            if handle.is_closed() {
                return ForwardOutcome::Reconnect(anyhow!(
                    "opening SSH direct-tcpip channel timed out after \
                     {SSH_CHANNEL_OPEN_TIMEOUT:?} on a closed session"
                ));
            }
            tracing::warn!(
                timeout_secs = SSH_CHANNEL_OPEN_TIMEOUT.as_secs(),
                "SSH direct-tcpip channel open timed out; keeping the healthy session"
            );
            return ForwardOutcome::Complete;
        }
    };

    let mut stream = channel.into_stream();
    let copied = tokio::io::copy_bidirectional(&mut local, &mut stream).await;
    if handle.is_closed() {
        return ForwardOutcome::Reconnect(anyhow!(
            "SSH session closed while forwarding direct-tcpip channel"
        ));
    }
    if let Err(error) = copied {
        tracing::debug!(error = %error, "ssh tunnel connection closed with an I/O error");
    }
    ForwardOutcome::Complete
}

fn local_port_of(listener: &TcpListener) -> u16 {
    listener.local_addr().map(|a| a.port()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_is_capped_exponential() {
        let base = Duration::from_secs(2);
        assert_eq!(reconnect_delay(base, 0), Duration::from_secs(2));
        assert_eq!(reconnect_delay(base, 1), Duration::from_secs(4));
        assert_eq!(reconnect_delay(base, 3), Duration::from_secs(16));
        // shift saturates at 6 → 2·64 = 128s, and stays there for higher attempts.
        assert_eq!(reconnect_delay(base, 6), Duration::from_secs(128));
        assert_eq!(reconnect_delay(base, 99), Duration::from_secs(128));
    }

    #[test]
    fn hardened_config_bounds_idle_sessions_and_detects_dead_peers() {
        let config = hardened_client_config();
        assert_eq!(config.keepalive_interval, Some(SSH_KEEPALIVE_INTERVAL));
        assert_eq!(config.keepalive_max, 3);
        assert_eq!(config.inactivity_timeout, Some(SSH_INACTIVITY_TIMEOUT));
        assert_eq!(
            config.preferred.compression.as_ref(),
            &[russh::compression::NONE]
        );
        assert!(config.nodelay);
    }

    #[test]
    fn forwarding_task_cap_applies_backpressure_at_exact_limit() {
        assert!(has_forward_capacity(0));
        assert!(has_forward_capacity(MAX_CONCURRENT_FORWARDS - 1));
        assert!(!has_forward_capacity(MAX_CONCURRENT_FORWARDS));
        assert!(!has_forward_capacity(MAX_CONCURRENT_FORWARDS + 1));
    }

    #[test]
    fn jump_chain_timeout_is_bounded() {
        assert_eq!(
            jump_chain_timeout(0),
            SSH_CONNECT_TIMEOUT + SSH_AUTH_TIMEOUT
        );
        assert_eq!(jump_chain_timeout(999), SSH_MAX_JUMP_CHAIN_TIMEOUT);
    }

    #[test]
    fn stable_session_window_is_longer_than_liveness_poll() {
        assert!(SSH_STABLE_SESSION_WINDOW > SSH_SESSION_HEALTH_INTERVAL);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_private_key_loader_holds_cap_and_blocks_a_second_worker() {
        let limiter = Arc::new(Semaphore::new(1));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(run_blocking_before_deadline(
            Arc::clone(&limiter),
            Instant::now() + Duration::from_millis(200),
            "SSH private-key loader",
            "private-key load deadline elapsed".to_owned(),
            move || {
                let _ = started_tx.send(());
                while !worker_release.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok::<(), anyhow::Error>(())
            },
        ));
        timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("first blocking loader did not start")
            .expect("first blocking loader dropped its start signal");

        let second_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_worker_started = Arc::clone(&second_started);
        let second = run_blocking_before_deadline(
            Arc::clone(&limiter),
            Instant::now() + Duration::from_millis(50),
            "SSH private-key loader",
            "second private-key load deadline elapsed".to_owned(),
            move || {
                second_worker_started.store(true, std::sync::atomic::Ordering::Release);
                Ok::<(), anyhow::Error>(())
            },
        )
        .await;
        let second_error =
            second.expect_err("second loader must time out while the orphan owns the permit");
        assert!(
            second_error.to_string().contains("deadline elapsed"),
            "unexpected second-loader timeout error: {second_error:#}"
        );
        assert!(
            !second_started.load(std::sync::atomic::Ordering::Acquire),
            "a second blocking loader escaped the concurrency cap"
        );

        let first_error = first
            .await
            .expect("first loader supervisor task panicked")
            .expect_err("slow first loader must not escape the auth deadline");
        release.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            first_error.to_string().contains("deadline elapsed"),
            "unexpected first-loader timeout error: {first_error:#}"
        );
        timeout(Duration::from_secs(1), async {
            while limiter.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("orphaned loader did not release its permit after worker completion");

        let fatal = fatal_ssh_configuration(first_error);
        assert!(
            is_fatal_ssh_configuration(&fatal),
            "private-key loader failures must suppress reconnect"
        );
    }

    #[test]
    fn tofu_outcomes_map_to_accept_decisions() {
        assert!(tofu_allows(&TofuOutcome::Accepted));
        assert!(tofu_allows(&TofuOutcome::Matched));
        assert!(!tofu_allows(&TofuOutcome::Changed {
            stored_key_base64: "x".into()
        }));
    }

    // endpoint_host_key_is_host_colon_port moved to `ssh_config.rs`
    // (runs on the default build there).
}
