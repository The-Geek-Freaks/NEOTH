//! TERMIX-01 — SSH local-port-forward tunnel (feature `ssh-tunnel`).
//!
//! Slice 1 (this file): the config types + the `russh` client [`Handler`] that
//! enforces host-key TOFU via [`super::ssh_tofu::TofuStore`]. The connect /
//! retry / forward state machine builds on these.
//!
//! Crypto: `russh` is pulled with the `ring` backend (NOT aws-lc-rs) so it
//! builds on Windows MSVC with no cmake/nasm.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use russh::client;
use russh::keys::ssh_key;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use super::ssh_tofu::{TofuOutcome, TofuStore};

/// Auth method for one SSH hop.
#[derive(Clone, Debug)]
pub enum SshAuth {
    /// Password auth.
    Password(String),
    /// Public-key auth from an on-disk OpenSSH private key.
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

/// One SSH endpoint — a jump hop or the final target.
#[derive(Clone, Debug)]
pub struct SshEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
}

impl SshEndpoint {
    /// Canonical `"host:port"` key for the TOFU host-key store.
    pub fn host_key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// A local-forward tunnel: SSH to `endpoint` (optionally through `jump_hosts`),
/// then forward `local_port` → `remote_host:remote_port` on the far side.
#[derive(Clone, Debug)]
pub struct SshTunnelConfig {
    pub endpoint: SshEndpoint,
    pub remote_host: String,
    pub remote_port: u16,
    /// Local listener port; `0` lets the OS assign one.
    pub local_port: u16,
    /// Ordered jump hosts (empty = direct). `jump_hosts[0]` is dialed first.
    pub jump_hosts: Vec<SshEndpoint>,
    pub max_retries: u32,
    pub retry_delay: Duration,
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
        let outcome = self
            .tofu
            .lock()
            .await
            .check_and_update(&self.host_key, &algo, repr.as_bytes())?;
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
    let handler = SshHandler::new(tofu, endpoint.host_key());
    let mut handle =
        client::connect(config, (endpoint.host.as_str(), endpoint.port), handler).await?;
    authenticate(&mut handle, endpoint).await?;
    Ok(handle)
}

/// Authenticate an already-connected handle for `endpoint`.
pub async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    endpoint: &SshEndpoint,
) -> Result<()> {
    let ok = match &endpoint.auth {
        SshAuth::Password(pw) => handle
            .authenticate_password(endpoint.username.clone(), pw.clone())
            .await?
            .success(),
        SshAuth::PrivateKey { path, passphrase } => {
            let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                .map_err(|e| anyhow!("load SSH key {}: {e}", path.display()))?;
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            handle
                .authenticate_publickey(endpoint.username.clone(), key)
                .await?
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

    /// Abort the tunnel's background task.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// Bind the local listener and spawn the connect → retry → forward loop. Returns
/// once the local port is bound (so `local_port()` is immediately usable); the
/// SSH connect proceeds in the background with exponential-backoff retry.
pub async fn spawn_tunnel(cfg: SshTunnelConfig, tofu: Arc<Mutex<TofuStore>>) -> Result<SshTunnel> {
    let listener = TcpListener::bind(("127.0.0.1", cfg.local_port)).await?;
    let local_port = listener.local_addr()?.port();
    let config = Arc::new(client::Config::default());
    let task = tokio::spawn(run_forward(listener, cfg, tofu, config));
    Ok(SshTunnel { local_port, task })
}

/// The connect/retry/forward driver. Reconnects (jump-aware) on transport loss
/// until `max_retries` consecutive connect failures, then gives up.
async fn run_forward(
    listener: TcpListener,
    cfg: SshTunnelConfig,
    tofu: Arc<Mutex<TofuStore>>,
    config: Arc<client::Config>,
) {
    let mut attempt = 0u32;
    loop {
        let handle =
            match super::ssh_jump::connect_via_jumps(&cfg.jump_hosts, &cfg.endpoint, tofu.clone(), config.clone())
                .await
            {
                Ok(h) => {
                    attempt = 0;
                    tracing::info!(host = %cfg.endpoint.host_key(), local_port = local_port_of(&listener), "ssh tunnel connected");
                    Arc::new(h)
                }
                Err(e) => {
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
        // Accept loop: forward each local connection over its own direct-tcpip
        // channel. Breaks (→ reconnect) on a listener error.
        loop {
            let (mut local, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "ssh tunnel: local accept failed");
                    break;
                }
            };
            let h = handle.clone();
            let remote_host = cfg.remote_host.clone();
            let remote_port = cfg.remote_port;
            tokio::spawn(async move {
                match h
                    .channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1", 0)
                    .await
                {
                    Ok(channel) => {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut local, &mut stream).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ssh tunnel: opening forward channel failed")
                    }
                }
            });
        }
    }
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
    fn tofu_outcomes_map_to_accept_decisions() {
        assert!(tofu_allows(&TofuOutcome::Accepted));
        assert!(tofu_allows(&TofuOutcome::Matched));
        assert!(!tofu_allows(&TofuOutcome::Changed {
            stored_key_base64: "x".into()
        }));
    }

    #[test]
    fn endpoint_host_key_is_host_colon_port() {
        let e = SshEndpoint {
            host: "h.example".into(),
            port: 2222,
            username: "u".into(),
            auth: SshAuth::Password("p".into()),
        };
        assert_eq!(e.host_key(), "h.example:2222");
    }
}
