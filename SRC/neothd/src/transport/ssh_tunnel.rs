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

#[cfg(test)]
mod tests {
    use super::*;

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
