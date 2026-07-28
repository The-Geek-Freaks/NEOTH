//! OS-attested, same-user transport for audit RPC.
//!
//! This module deliberately has no TCP fallback.  The audit endpoint is either
//! a private Unix-domain socket or a current-TokenUser-only Windows named pipe.
//! Both server and client attest the peer before returning a usable stream.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};

const ENDPOINT_NONCE_HEX_LEN: usize = 32;
const HOME_SHA256_HEX_LEN: usize = 64;
const MAX_BLOCKING_REQUEST_BYTES: usize = 8 * 1024;
const MAX_BLOCKING_RESPONSE_BYTES: usize = 1024 * 1024;

/// Strict sidecar representation for the second-generation audit endpoint.
///
/// The endpoint contains enough binding material for `connect` to reject a
/// syntactically valid but attacker-selected path/name even when the caller
/// does not also have the NEOTH home path at hand.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AuditEndpointV2 {
    #[cfg(unix)]
    UnixSocket {
        path: PathBuf,
        endpoint_nonce: String,
        home_sha256: String,
    },
    #[cfg(windows)]
    WindowsNamedPipe {
        name: String,
        endpoint_nonce: String,
        home_sha256: String,
    },
}

/// Trait-object boundary shared by Unix sockets and Windows named pipes.
pub(crate) trait AuditIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AuditIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type AuditStream = Box<dyn AuditIo>;

/// Platform listener.  Its `accept` method authenticates the OS peer before it
/// yields the stream, so callers can acquire connection semaphores afterwards.
pub(crate) struct AuditListener {
    #[cfg(unix)]
    inner: unix::Listener,
    #[cfg(windows)]
    inner: windows::Listener,
    #[cfg(not(any(unix, windows)))]
    _unsupported: (),
}

impl AuditEndpointV2 {
    /// Validate a sidecar endpoint against the canonical home and boot nonce.
    pub(crate) fn validate(&self, home: &Path, expected_nonce: &str) -> Result<()> {
        let expected = endpoint_for_home(home, expected_nonce)?;
        ensure!(
            self == &expected,
            "audit-RPC endpoint does not match canonical home and endpoint nonce"
        );
        self.validate_shape()
    }

    fn validate_shape(&self) -> Result<()> {
        match self {
            #[cfg(unix)]
            Self::UnixSocket {
                path,
                endpoint_nonce,
                home_sha256,
            } => unix::validate_endpoint_shape(path, endpoint_nonce, home_sha256),
            #[cfg(windows)]
            Self::WindowsNamedPipe {
                name,
                endpoint_nonce,
                home_sha256,
            } => windows::validate_endpoint_shape(name, endpoint_nonce, home_sha256),
        }
    }
}

/// Deterministically derive the only endpoint accepted for this home + nonce.
pub(crate) fn endpoint_for_home(home: &Path, endpoint_nonce: &str) -> Result<AuditEndpointV2> {
    validate_endpoint_nonce(endpoint_nonce)?;
    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize NEOTH home {}", home.display()))?;
    let home_sha256 = canonical_home_sha256(&canonical_home);

    #[cfg(unix)]
    {
        let runtime_name = unix::runtime_directory_name(&home_sha256, endpoint_nonce);
        return Ok(AuditEndpointV2::UnixSocket {
            path: canonical_home.join(runtime_name).join("audit.sock"),
            endpoint_nonce: endpoint_nonce.to_owned(),
            home_sha256,
        });
    }

    #[cfg(windows)]
    {
        return Ok(AuditEndpointV2::WindowsNamedPipe {
            name: windows::pipe_name(&home_sha256, endpoint_nonce),
            endpoint_nonce: endpoint_nonce.to_owned(),
            home_sha256,
        });
    }

    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("audit-RPC OS transport is unsupported on this platform")
}

/// Bind an authenticated OS-local endpoint.  Existing names always fail
/// closed; neither platform silently reuses or removes an unowned endpoint.
pub(crate) async fn bind(
    home: &Path,
    endpoint_nonce: &str,
) -> Result<(AuditListener, AuditEndpointV2)> {
    let endpoint = endpoint_for_home(home, endpoint_nonce)?;

    #[cfg(unix)]
    {
        let listener = unix::Listener::bind(&endpoint)?;
        return Ok((AuditListener { inner: listener }, endpoint));
    }

    #[cfg(windows)]
    {
        let listener = windows::Listener::bind(&endpoint)?;
        return Ok((AuditListener { inner: listener }, endpoint));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = endpoint;
        anyhow::bail!("audit-RPC OS transport is unsupported on this platform")
    }
}

impl AuditListener {
    /// Accept one connection and verify the peer's effective OS identity before
    /// returning it to the RPC layer.
    pub(crate) async fn accept(&mut self) -> Result<AuditStream> {
        #[cfg(unix)]
        {
            return self.inner.accept().await;
        }

        #[cfg(windows)]
        {
            return self.inner.accept().await;
        }

        #[cfg(not(any(unix, windows)))]
        anyhow::bail!("audit-RPC OS transport is unsupported on this platform")
    }
}

/// Connect asynchronously and attest the server as the current OS user.
pub(crate) async fn connect(endpoint: &AuditEndpointV2) -> Result<AuditStream> {
    endpoint.validate_shape()?;

    #[cfg(unix)]
    {
        return unix::connect(endpoint).await;
    }

    #[cfg(windows)]
    {
        return windows::connect(endpoint).await;
    }

    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("audit-RPC OS transport is unsupported on this platform")
}

/// Blocking request/response helper for synchronous reachability checks.
///
/// It does not construct or enter a Tokio runtime.  Request and response sizes
/// and the entire exchange wall-clock are bounded, including the Windows
/// overlapped-I/O waits.
pub(crate) fn exchange_blocking(
    endpoint: &AuditEndpointV2,
    request: &[u8],
    max_response: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    endpoint.validate_shape()?;
    ensure!(
        request.len() <= MAX_BLOCKING_REQUEST_BYTES,
        "audit-RPC blocking request exceeds {MAX_BLOCKING_REQUEST_BYTES} bytes"
    );
    ensure!(
        max_response <= MAX_BLOCKING_RESPONSE_BYTES,
        "audit-RPC blocking response cap exceeds {MAX_BLOCKING_RESPONSE_BYTES} bytes"
    );
    ensure!(!timeout.is_zero(), "audit-RPC timeout must be non-zero");

    #[cfg(unix)]
    {
        return unix::exchange_blocking(endpoint, request, max_response, timeout);
    }

    #[cfg(windows)]
    {
        return windows::exchange_blocking(endpoint, request, max_response, timeout);
    }

    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("audit-RPC OS transport is unsupported on this platform")
}

fn validate_endpoint_nonce(nonce: &str) -> Result<()> {
    validate_lower_hex(nonce, ENDPOINT_NONCE_HEX_LEN, "audit-RPC endpoint nonce")
}

fn validate_home_sha256(home_sha256: &str) -> Result<()> {
    validate_lower_hex(
        home_sha256,
        HOME_SHA256_HEX_LEN,
        "audit-RPC canonical-home SHA-256",
    )
}

fn validate_lower_hex(value: &str, exact_len: usize, label: &str) -> Result<()> {
    ensure!(
        value.len() == exact_len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must be exactly {exact_len} lowercase hex characters"
    );
    Ok(())
}

#[cfg(unix)]
fn channel_hash(home_sha256: &str, endpoint_nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"neoth-audit-rpc-v2\0");
    hasher.update(home_sha256.as_bytes());
    hasher.update([0]);
    hasher.update(endpoint_nonce.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(unix)]
fn canonical_home_sha256(home: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    hex::encode(Sha256::digest(home.as_os_str().as_bytes()))
}

#[cfg(windows)]
fn canonical_home_sha256(home: &Path) -> String {
    use std::os::windows::ffi::OsStrExt as _;

    let mut encoded = Vec::new();
    for unit in home.as_os_str().encode_wide() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    hex::encode(Sha256::digest(encoded))
}

#[cfg(not(any(unix, windows)))]
fn canonical_home_sha256(home: &Path) -> String {
    hex::encode(Sha256::digest(
        home.as_os_str().to_string_lossy().as_bytes(),
    ))
}

#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
