//! TERMIX-01 — SSH tunnel CONFIG types (unconditional).
//!
//! Split out of `ssh_tunnel.rs` so the private
//! `credentials.yaml::ssh_tunnels` authority parses and round-trips on every
//! build. Historical `freedom.yaml::ssh_tunnels` blocks are atomically
//! migrated into that private authority before runtime activation. The
//! russh-dependent runtime stays behind the feature in `ssh_tunnel.rs`, which
//! re-exports these types.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Auth method for one SSH hop.
///
/// YAML forms (externally tagged, snake_case):
/// ```yaml
/// auth:
///   password: "app-password"
/// # or
/// auth:
///   private_key:
///     path: "C:/Users/op/.ssh/id_ed25519"
///     passphrase: null
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuth {
    /// Password auth.
    Password(SecretString),
    /// Public-key auth from an on-disk OpenSSH private key.
    PrivateKey {
        path: PathBuf,
        #[serde(default)]
        passphrase: Option<SecretString>,
    },
}

impl PartialEq for SshAuth {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Password(left), Self::Password(right)) => {
                left.expose_secret() == right.expose_secret()
            }
            (
                Self::PrivateKey {
                    path: left_path,
                    passphrase: left_passphrase,
                },
                Self::PrivateKey {
                    path: right_path,
                    passphrase: right_passphrase,
                },
            ) => {
                left_path == right_path
                    && left_passphrase.as_ref().map(SecretString::expose_secret)
                        == right_passphrase.as_ref().map(SecretString::expose_secret)
            }
            _ => false,
        }
    }
}

impl Eq for SshAuth {}

// Manual Debug: the password / passphrase are secrets — a `{:?}` of a
// tunnel config in a log line or error context must never print them.
impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::Password(_) => f.write_str("Password(<redacted>)"),
            SshAuth::PrivateKey { path, passphrase } => f
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
        }
    }
}

/// One SSH endpoint — a jump hop or the final target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshEndpoint {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    /// `singleton_map`: serde_yaml 0.9 renders externally-tagged enums as
    /// `!tag` — the map form (`auth: {password: …}`) is what operators
    /// expect in credentials.yaml.
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub auth: SshAuth,
}

fn default_ssh_port() -> u16 {
    22
}

impl SshEndpoint {
    /// Canonical `"host:port"` key for the TOFU host-key store.
    pub fn host_key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// A local-forward tunnel: SSH to `endpoint` (optionally through `jump_hosts`),
/// then forward `local_port` → `remote_host:remote_port` on the far side.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshTunnelConfig {
    pub endpoint: SshEndpoint,
    pub remote_host: String,
    pub remote_port: u16,
    /// Local listener port; `0` (default) lets the OS assign one.
    #[serde(default)]
    pub local_port: u16,
    /// Ordered jump hosts (empty = direct). `jump_hosts[0]` is dialed first.
    #[serde(default)]
    pub jump_hosts: Vec<SshEndpoint>,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base reconnect delay; exponential backoff doubles it per attempt
    /// (capped). YAML key is seconds: `retry_delay_secs: 2`.
    #[serde(
        default = "default_retry_delay",
        rename = "retry_delay_secs",
        with = "duration_secs"
    )]
    pub retry_delay: Duration,
}

fn default_max_retries() -> u32 {
    5
}

fn default_retry_delay() -> Duration {
    Duration::from_secs(2)
}

/// serde shim: `Duration` ⇄ whole seconds (`u64`) for operator-facing YAML.
mod duration_secs {
    use std::time::Duration;

    pub fn serialize<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = <u64 as serde::Deserialize>::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_config_yaml_round_trips_private_key_auth() {
        let cfg = SshTunnelConfig {
            endpoint: SshEndpoint {
                host: "bastion.example".into(),
                port: 2222,
                username: "op".into(),
                auth: SshAuth::PrivateKey {
                    path: PathBuf::from("/home/op/.ssh/id_ed25519"),
                    passphrase: Some("pp".into()),
                },
            },
            remote_host: "10.0.0.5".into(),
            remote_port: 5432,
            local_port: 0,
            jump_hosts: vec![],
            max_retries: 5,
            retry_delay: Duration::from_secs(2),
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: SshTunnelConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, cfg);
        assert!(yaml.contains("retry_delay_secs: 2"), "seconds key: {yaml}");
    }

    #[test]
    fn tunnel_config_yaml_round_trips_password_auth_with_defaults() {
        // Minimal operator YAML: only required keys; defaults fill the rest.
        let yaml = r#"
endpoint:
  host: h.example
  username: u
  auth:
    password: "pw"
remote_host: 127.0.0.1
remote_port: 8080
"#;
        let cfg: SshTunnelConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.endpoint.port, 22, "default ssh port");
        assert_eq!(cfg.local_port, 0);
        assert!(cfg.jump_hosts.is_empty());
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.retry_delay, Duration::from_secs(2));
        assert_eq!(cfg.endpoint.auth, SshAuth::Password("pw".into()));
        // And it re-serializes cleanly.
        let round: SshTunnelConfig =
            serde_yaml::from_str(&serde_yaml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(round, cfg);
    }

    #[test]
    fn ssh_auth_debug_never_prints_secrets() {
        let pw = SshAuth::Password("hunter2".into());
        let dbg = format!("{pw:?}");
        assert!(!dbg.contains("hunter2"), "password leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));

        let key = SshAuth::PrivateKey {
            path: PathBuf::from("/k"),
            passphrase: Some("s3cret".into()),
        };
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("s3cret"), "passphrase leaked: {dbg}");
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
