//! Windows adapter for the audit-specific endpoint record.
//!
//! Pipe creation, protected current-TokenUser DACL verification, remote-peer
//! refusal, SID attestation, and bounded overlapped I/O live in
//! [`crate::windows_private_ipc`]. Audit keeps its own endpoint schema, token,
//! and sidecar authority here.

use std::time::Duration;

use anyhow::{Result, ensure};

use super::{AuditEndpointV2, AuditStream};
use crate::windows_private_ipc::{
    ExchangeBounds, Listener as PrivatePipeListener, PrivatePipeEndpoint,
};

const SERVICE: &str = "neoth-audit-v2";
const PIPE_BUFFER_BYTES: u32 = 8 * 1024;

pub(super) struct Listener {
    inner: PrivatePipeListener,
}

pub(super) fn pipe_name(home_sha256: &str, endpoint_nonce: &str) -> String {
    // This preserves the historic audit endpoint spelling while making its
    // service/home/nonce binding canonical in the shared primitive.
    format!(r"\\.\pipe\{SERVICE}-{home_sha256}-{endpoint_nonce}")
}

pub(super) fn validate_endpoint_shape(
    name: &str,
    endpoint_nonce: &str,
    home_sha256: &str,
) -> Result<()> {
    super::validate_endpoint_nonce(endpoint_nonce)?;
    super::validate_home_sha256(home_sha256)?;
    let endpoint = PrivatePipeEndpoint::derive(SERVICE, home_sha256, endpoint_nonce)?;
    ensure!(
        name == endpoint.name(),
        "audit-RPC named-pipe name is not bound to home and endpoint nonce"
    );
    Ok(())
}

impl Listener {
    pub(super) fn bind(endpoint: &AuditEndpointV2) -> Result<Self> {
        Ok(Self {
            inner: PrivatePipeListener::bind(private_endpoint(endpoint)?, PIPE_BUFFER_BYTES)?,
        })
    }

    pub(super) async fn accept(&mut self) -> Result<AuditStream> {
        Ok(Box::new(self.inner.accept().await?))
    }
}

pub(super) async fn connect(endpoint: &AuditEndpointV2) -> Result<AuditStream> {
    Ok(Box::new(
        crate::windows_private_ipc::connect(&private_endpoint(endpoint)?).await?,
    ))
}

pub(super) fn exchange_blocking(
    endpoint: &AuditEndpointV2,
    request: &[u8],
    max_response: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    crate::windows_private_ipc::exchange_blocking(
        &private_endpoint(endpoint)?,
        request,
        ExchangeBounds {
            max_request_bytes: super::MAX_BLOCKING_REQUEST_BYTES,
            max_response_bytes: max_response,
            timeout,
        },
    )
}

fn private_endpoint(endpoint: &AuditEndpointV2) -> Result<PrivatePipeEndpoint> {
    let AuditEndpointV2::WindowsNamedPipe {
        name,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    validate_endpoint_shape(name, endpoint_nonce, home_sha256)?;
    PrivatePipeEndpoint::derive(SERVICE, home_sha256, endpoint_nonce)
}

#[cfg(test)]
pub(super) use crate::windows_private_ipc::{
    attest_client_sid_with, current_process_sid, same_sid,
};
