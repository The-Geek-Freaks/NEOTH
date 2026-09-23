//! AUDIT-RPC-01 — the one-shot CLI client side.
//!
//! The client uses only the OS-authenticated same-user endpoint advertised by
//! the strict local sidecar. No TCP or remote-network fallback exists.

use std::path::Path;

#[cfg(any(unix, windows))]
use anyhow::Context as _;
use anyhow::Result;
use base64::Engine;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::sidecar::read_sidecar;
use super::token::read_rpc_token;

const MAX_RPC_RESPONSE_BYTES: usize = 1024 * 1024;
const RPC_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// The core watchdog owns the 120-second meaningful-progress boundary. The
/// attach reader keeps only a small delivery margin so a legitimate final
/// watchdog frame is not preempted by a shorter client idle deadline.
const GUI_CHAT_ATTACH_TERMINAL_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);
/// Bound the entire local health exchange, including local connect, peer
/// attestation, request write, response read, and scheduling delays.
const HEALTH_CHECK_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum AuditRpcClientError {
    #[error("audit-RPC unavailable: {0}")]
    Unavailable(String),
    #[error("audit-RPC daemon refused the frame: HTTP {0}")]
    Refused(u16),
}

/// W39 distinguishes the only fallback-safe phase from every outcome after a
/// request could have reached the daemon.  A caller may use its standalone
/// path only for [`PreWriteUnavailable`]; refusal, EOF, malformed replies,
/// write failures and deadlines must never cause a second provider turn.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DaemonPlainChatClientError {
    #[error("daemon plain-chat unavailable before request write: {0}")]
    PreWriteUnavailable(String),
    #[error("daemon plain-chat refused the request: HTTP {0}")]
    Refused(u16),
    #[error(
        "daemon plain-chat provider made no meaningful progress for {timeout_seconds}s; retryable: {retryable}"
    )]
    TurnSilenceTimeout {
        timeout_seconds: u64,
        retryable: bool,
    },
    #[error("daemon plain-chat outcome is indeterminate after request write: {0}")]
    Indeterminate(String),
}

impl DaemonPlainChatClientError {
    pub(crate) fn allows_standalone_fallback(&self) -> bool {
        matches!(self, Self::PreWriteUnavailable(_))
    }
}

/// Fail-closed reason for a synchronous audit-RPC health probe. This is kept
/// crate-visible so integration tests and operator-facing callers can retain
/// the public boolean API while exposing the precise rejected security gate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AuditRpcHealthError {
    #[error("audit-RPC health sidecar rejected: {0}")]
    Sidecar(String),
    #[error("audit-RPC health sidecar PID {pid} does not own the exact endpoint")]
    ExactDaemonOwner { pid: u32 },
    #[error("audit-RPC health bearer token rejected: {0}")]
    Token(String),
    #[error("audit-RPC health transport or peer attestation rejected: {0}")]
    TransportOrPeer(String),
    #[error("audit-RPC health endpoint returned HTTP {0}, expected 200")]
    Status(u16),
    #[error("audit-RPC health endpoint returned an unexpected exact body ({bytes} bytes)")]
    Body { bytes: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstanceCommitment(pub(crate) String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonInstanceProof {
    pub(crate) daemon_pid: u32,
    pub(crate) instance_commitment: InstanceCommitment,
}

pub(crate) fn instance_commitment_for_nonce(nonce: &str) -> InstanceCommitment {
    let mut digest = Sha256::new();
    digest.update(b"neoth/channel-runtime-health-instance/v1");
    digest.update(nonce.as_bytes());
    InstanceCommitment(hex::encode(digest.finalize()))
}

/// Authenticated same-user IPC health probe. Sidecar/PID checks bind discovery
/// to the live daemon incarnation; the transport additionally proves the OS
/// user before the bearer is sent.
pub fn is_reachable(home: &Path) -> bool {
    authenticated_live_instance(home).is_ok()
}

/// Run the same fail-closed reachability probe as [`is_reachable`], preserving
/// the rejection category for diagnostics. This never sends the bearer until
/// strict sidecar and exact PID/nonce/lock ownership checks have succeeded.
pub(crate) fn authenticated_live_instance(
    home: &Path,
) -> std::result::Result<DaemonInstanceProof, AuditRpcHealthError> {
    let sidecar =
        read_sidecar(home).map_err(|error| AuditRpcHealthError::Sidecar(error.to_string()))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(AuditRpcHealthError::ExactDaemonOwner { pid: sidecar.pid });
    }
    let token =
        read_rpc_token(home).map_err(|error| AuditRpcHealthError::Token(error.to_string()))?;
    let request = format!(
        "POST /health HTTP/1.1\r\n\
         Host: neoth-local\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 2\r\n\
         Connection: close\r\n\
         \r\n\
         {{}}"
    );
    let response = super::transport::exchange_blocking(
        &sidecar.endpoint,
        request.as_bytes(),
        4096,
        HEALTH_CHECK_EXCHANGE_TIMEOUT,
    )
    .map_err(|error| AuditRpcHealthError::TransportOrPeer(error.to_string()))?;
    validate_health_response(response)?;
    Ok(DaemonInstanceProof {
        daemon_pid: sidecar.pid,
        instance_commitment: instance_commitment_for_nonce(&sidecar.endpoint_nonce),
    })
}

#[cfg(test)]
pub(crate) fn health_check(home: &Path) -> std::result::Result<(), AuditRpcHealthError> {
    authenticated_live_instance(home).map(|_| ())
}

fn validate_health_response(response: Vec<u8>) -> std::result::Result<(), AuditRpcHealthError> {
    let (status, response) = parse_rpc_response(response)
        .map_err(|error| AuditRpcHealthError::TransportOrPeer(error.to_string()))?;
    if status != 200 {
        return Err(AuditRpcHealthError::Status(status));
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        // `parse_rpc_response` has already proved the separator exists. Keep
        // this defensive branch fail-closed if that invariant ever changes.
        .ok_or_else(|| {
            AuditRpcHealthError::TransportOrPeer(
                "parsed health response lost its header boundary".into(),
            )
        })?;
    if body == "{\"ok\":true}" {
        Ok(())
    } else {
        Err(AuditRpcHealthError::Body { bytes: body.len() })
    }
}

fn exact_daemon_owner(home: &Path, pid: u32, endpoint_nonce: &str) -> bool {
    let pidfile = home.join("neothd.pid");
    crate::daemon::pidfile::live_daemon_endpoint(&pidfile, pid, endpoint_nonce).unwrap_or(false)
}

/// Return the live daemon's PID-lock-bound endpoint nonce for a sibling local
/// authority. This exposes no audit bearer and never accepts caller-supplied
/// nonce material.
#[cfg(any(unix, windows))]
pub(crate) fn verified_daemon_endpoint_nonce(home: &Path) -> Result<String> {
    let sidecar = read_sidecar(home).context("read audit-RPC daemon discovery")?;
    anyhow::ensure!(
        exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce),
        "audit-RPC sidecar daemon PID does not own the exact endpoint"
    );
    Ok(sidecar.endpoint_nonce)
}

/// Core-only bridge discovery. The returned commitment is the authenticated
/// daemon-instance boot binding used by the W41 runtime; no GUI caller can
/// provide or override it.
pub(crate) fn attested_gui_chat_boot_id(home: &Path) -> Result<String> {
    authenticated_live_instance(home)
        .map(|proof| proof.instance_commitment.0)
        .map_err(|error| anyhow::anyhow!("attest GUI chat instance: {error}"))
}

/// AUDIT-RPC-01 #1 — fail-closed pre-flight for one-shot PERMISSION actions.
///
/// When `required` is set by the caller (either its configured compliance
/// posture or an action-specific hard requirement) AND a daemon is live (it
/// owns the WAL writer, so the one-shot can't audit
/// locally) AND the daemon's audit-RPC listener is NOT reachable, returns an
/// error so the caller REFUSES the action — a permission action must never run
/// without an audit record under a compliance/proof posture. No-op when the
/// flag is off, no daemon is live (the one-shot writes its own frame), or the
/// listener is reachable.
pub fn enforce_required_audit(required: bool, daemon_live: bool, home: &Path) -> Result<()> {
    if required && daemon_live && !is_reachable(home) {
        anyhow::bail!(
            "required permission auditing is active for this action and a daemon owns the WAL, but \
             its audit-RPC listener is unreachable — refusing the action so it isn't performed \
             un-audited. Restart the daemon and inspect its same-user IPC/PID discovery, or stop \
             the daemon so the one-shot can own its WAL writer."
        );
    }
    Ok(())
}

/// Forward an audit intent to the running daemon. `payload` is the exact frame
/// payload the one-shot would have written itself. Returns `Ok(())` once the
/// daemon confirms the append (HTTP 200). On ANY availability failure (no
/// sidecar / no token / connect refused) returns `Unavailable` so the caller can
/// fall back to its existing un-audited path — the action itself is already
/// gated; this only governs whether the audit frame lands.
pub async fn try_post_audit_frame(
    home: &Path,
    event_type: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    try_post_audit_frame_with_subtype(home, event_type, 0, payload).await
}

/// Subtype-aware audit forwarder. Existing callers keep using
/// [`try_post_audit_frame`] (subtype zero); EXTENDED events must use this
/// function with `(event_type=0x00, event_subtype!=0)`. The server validates
/// the exact pair against its compile-time allowlist.
pub async fn try_post_audit_frame_with_subtype(
    home: &Path,
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    try_post_frame_to_path(home, "/audit", event_type, event_subtype, payload).await
}

/// Mandatory internal Skill-mutation transport. This route remains available
/// whenever the daemon owns the WAL even when the operator disables the
/// optional public audit/token API.
pub(crate) async fn try_post_skill_mutation_frame(
    home: &Path,
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    try_post_frame_to_path(
        home,
        "/skill-mutation-audit",
        event_type,
        event_subtype,
        payload,
    )
    .await
}

async fn try_post_frame_to_path(
    home: &Path,
    path: &str,
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    let sidecar =
        read_sidecar(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(AuditRpcClientError::Unavailable(format!(
            "stale audit-RPC sidecar (daemon pid {} does not own the endpoint)",
            sidecar.pid
        )));
    }
    let token =
        read_rpc_token(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let body = format!(
        "{{\"event_type\":{event_type},\"event_subtype\":{event_subtype},\"payload_b64\":{payload_b64:?}}}",
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: neoth-local\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    let (status, _) = exchange_rpc(sidecar.endpoint, req).await?;
    if status == 200 {
        Ok(())
    } else {
        Err(AuditRpcClientError::Refused(status))
    }
}

/// Reconcile a previously persisted durable admission with the daemon-owned
/// writer. Availability errors are indeterminate: callers retain the exact
/// descriptor and must never replace this operation with a fresh Gate call.
pub(crate) async fn try_post_trust_decision_once(
    home: &Path,
    expected: &crate::permissions::trust_ledger::TrustAdmissionDescriptor,
) -> std::result::Result<
    crate::permissions::trust_ledger::TrustDecisionOnceOutcome,
    crate::permissions::trust_ledger::TrustDecisionOnceError,
> {
    use crate::permissions::trust_ledger::TrustDecisionOnceError;

    expected
        .validate()
        .map_err(|_| TrustDecisionOnceError::Indeterminate)?;
    let body = serde_json::to_string(&super::TrustDecisionOnceRequest {
        schema_version: 1,
        descriptor: expected.clone(),
    })
    .map_err(|_| TrustDecisionOnceError::Indeterminate)?;
    if body.len() > 4096 {
        return Err(TrustDecisionOnceError::Indeterminate);
    }
    let (status, response) = post_rpc(home, "/trust-decision-once", &body)
        .await
        .map_err(|_| TrustDecisionOnceError::Indeterminate)?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or(TrustDecisionOnceError::Indeterminate)?;
    if status != 200 {
        return Err(parse_trust_decision_refusal(status, body));
    }
    parse_trust_decision_response(body).map_err(|_| TrustDecisionOnceError::Indeterminate)
}

/// Only the two closed conflict codes distinguish terminal failures. Missing,
/// extended, malformed or unexpected replies preserve the unknown outcome.
pub(super) fn parse_trust_decision_refusal(
    status: u16,
    body: &str,
) -> crate::permissions::trust_ledger::TrustDecisionOnceError {
    use crate::permissions::trust_ledger::TrustDecisionOnceError;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Refusal {
        error: RefusalCode,
    }
    #[derive(serde::Deserialize)]
    enum RefusalCode {
        #[serde(rename = "trust_admission_conflict")]
        Conflict,
        #[serde(rename = "trust_admission_duplicate")]
        Duplicate,
    }
    if status != 409 {
        return TrustDecisionOnceError::Indeterminate;
    }
    match serde_json::from_str::<Refusal>(body) {
        Ok(Refusal {
            error: RefusalCode::Conflict,
        }) => TrustDecisionOnceError::Conflict,
        Ok(Refusal {
            error: RefusalCode::Duplicate,
        }) => TrustDecisionOnceError::Duplicate,
        Err(_) => TrustDecisionOnceError::Indeterminate,
    }
}

pub(super) fn parse_trust_decision_response(
    body: &str,
) -> std::result::Result<
    crate::permissions::trust_ledger::TrustDecisionOnceOutcome,
    AuditRpcClientError,
> {
    use crate::permissions::trust_ledger::TrustDecisionOnceOutcome;

    let response: super::TrustDecisionOnceResponse = serde_json::from_str(body)
        .map_err(|_| AuditRpcClientError::Unavailable("invalid trust admission response".into()))?;
    if response.schema_version != 1 {
        return Err(AuditRpcClientError::Unavailable(
            "unsupported trust admission response version".into(),
        ));
    }
    Ok(match response.outcome {
        super::TrustDecisionOnceWireOutcome::ExistingExact => {
            TrustDecisionOnceOutcome::ExistingExact
        }
        super::TrustDecisionOnceWireOutcome::AppendedExact => {
            TrustDecisionOnceOutcome::AppendedExact
        }
    })
}

/// Submit one eligible ordinary plaintext turn to the live same-user daemon.
/// This function intentionally has no `ChatArgs` input: CLI routing decides
/// eligibility before calling it and a request carries no parser authority.
pub(crate) async fn try_daemon_plain_chat_turn(
    home: &Path,
    message: String,
) -> std::result::Result<super::DaemonPlainChatResponse, DaemonPlainChatClientError> {
    let request = super::DaemonPlainChatRequest {
        schema_version: super::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
        message,
    };
    super::validate_daemon_plain_chat_request(&request)
        .map_err(|reason| DaemonPlainChatClientError::PreWriteUnavailable(reason.into()))?;
    let body = serde_json::to_string(&request).map_err(|error| {
        DaemonPlainChatClientError::PreWriteUnavailable(format!(
            "serialize sealed request: {error}"
        ))
    })?;
    if body.len() > super::DAEMON_PLAIN_CHAT_TRANSPORT_BODY_MAX_BYTES {
        return Err(DaemonPlainChatClientError::PreWriteUnavailable(
            "sealed request exceeds the transport body cap".into(),
        ));
    }
    let sidecar = read_sidecar(home).map_err(|error| {
        DaemonPlainChatClientError::PreWriteUnavailable(format!("sidecar: {error}"))
    })?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(DaemonPlainChatClientError::PreWriteUnavailable(format!(
            "stale audit-RPC sidecar (daemon pid {} does not own the endpoint)",
            sidecar.pid
        )));
    }
    let token = read_rpc_token(home).map_err(|error| {
        DaemonPlainChatClientError::PreWriteUnavailable(format!("token: {error}"))
    })?;
    let wire_request = [
        "POST /chat/turn HTTP/1.1".to_string(),
        "Host: neoth-local".to_string(),
        format!("Authorization: Bearer {token}"),
        "Content-Type: application/json".to_string(),
        format!("Content-Length: {}", body.len()),
        "Connection: close".to_string(),
        String::new(),
        body,
    ]
    .join("\r\n");

    // A connection failure occurs before any request byte is attempted.  The
    // subsequent write/read interval is deliberately one indeterminate phase:
    // even a `write_all` error may follow a partial OS pipe write.
    let endpoint = sidecar.endpoint;
    let endpoint_label = format!("{endpoint:?}");
    let mut stream =
        tokio::time::timeout(RPC_EXCHANGE_TIMEOUT, super::transport::connect(&endpoint))
            .await
            .map_err(|_| {
                DaemonPlainChatClientError::PreWriteUnavailable(format!(
                    "connect {endpoint_label} exceeded the {}s deadline",
                    RPC_EXCHANGE_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|error| {
                DaemonPlainChatClientError::PreWriteUnavailable(format!(
                    "connect {endpoint_label}: {error}"
                ))
            })?;
    tokio::time::timeout(
        RPC_EXCHANGE_TIMEOUT,
        stream.write_all(wire_request.as_bytes()),
    )
    .await
    .map_err(|_| DaemonPlainChatClientError::Indeterminate("chat request write deadline".into()))?
    .map_err(|error| DaemonPlainChatClientError::Indeterminate(format!("write: {error}")))?;
    // Do not impose a total response deadline here. A daemon-owned provider
    // can make legitimate meaningful progress beyond 125 seconds; the shared
    // turn watchdog is the authority that publishes its typed timeout.
    let (status, response) = read_rpc_response_with_limit(
        &mut stream,
        super::DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES.saturating_add(4096),
    )
    .await
    .map_err(|error| DaemonPlainChatClientError::Indeterminate(error.to_string()))?;
    let response_body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| {
            DaemonPlainChatClientError::Indeterminate(
                "parsed chat response lost its header boundary".into(),
            )
        })?;
    if status != 200 {
        if let Ok(error) =
            serde_json::from_str::<super::DaemonPlainChatErrorResponse>(response_body)
            && super::validate_daemon_plain_chat_error_response(&error).is_ok()
        {
            return match error.code {
                super::DaemonPlainChatErrorCode::TurnSilenceTimeout => {
                    Err(DaemonPlainChatClientError::TurnSilenceTimeout {
                        timeout_seconds: error.timeout_seconds,
                        retryable: error.retryable,
                    })
                }
            };
        }
        return Err(DaemonPlainChatClientError::Refused(status));
    }
    let response: super::DaemonPlainChatResponse =
        serde_json::from_str(response_body).map_err(|_| {
            DaemonPlainChatClientError::Indeterminate("invalid sealed chat response".into())
        })?;
    super::validate_daemon_plain_chat_response(&response, response_body.len())
        .map_err(|reason| DaemonPlainChatClientError::Indeterminate(reason.into()))?;
    Ok(response)
}

/// W41 GUI bridge errors keep pre-write discovery distinct from an exchanged request.
#[allow(dead_code)] // Private diagnostics stay available without exposing raw details in GUI errors.
#[derive(Debug)]
pub(crate) enum GuiChatClientError {
    PreWriteUnavailable(String),
    Indeterminate(String),
    Refused(u16, String),
}

pub(crate) async fn gui_chat_post<T, R>(
    home: &Path,
    path: &str,
    request: &T,
) -> Result<R, GuiChatClientError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_string(request)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("serialize: {e}")))?;
    if body.len() > super::DAEMON_PLAIN_CHAT_TRANSPORT_BODY_MAX_BYTES {
        return Err(GuiChatClientError::PreWriteUnavailable(
            "GUI request exceeds transport cap".into(),
        ));
    }
    let sidecar = read_sidecar(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("sidecar: {e}")))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(GuiChatClientError::PreWriteUnavailable(
            "stale audit-RPC sidecar".into(),
        ));
    }
    let token = read_rpc_token(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("token: {e}")))?;
    let wire = format!(
        "POST {path} HTTP/1.1\r\nHost: neoth-local\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let endpoint = sidecar.endpoint;
    let mut stream =
        tokio::time::timeout(RPC_EXCHANGE_TIMEOUT, super::transport::connect(&endpoint))
            .await
            .map_err(|_| GuiChatClientError::PreWriteUnavailable("connect deadline".into()))
            .and_then(|result| {
                result.map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("connect: {e}")))
            })?;
    let (status, raw) = tokio::time::timeout(super::CHAT_TURN_RESPONSE_TIMEOUT, async {
        stream
            .write_all(wire.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        read_rpc_response_with_limit(
            &mut stream,
            super::DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES.saturating_add(4096),
        )
        .await
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| GuiChatClientError::Indeterminate("GUI response deadline".into()))?
    .map_err(GuiChatClientError::Indeterminate)?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| GuiChatClientError::Indeterminate("missing response boundary".into()))?;
    if status != 200 {
        return Err(GuiChatClientError::Refused(status, body.into()));
    }
    serde_json::from_str(body)
        .map_err(|_| GuiChatClientError::Indeterminate("malformed sealed GUI response".into()))
}

#[allow(dead_code)]
async fn gui_chat_post_raw<T: serde::Serialize>(
    home: &Path,
    path: &str,
    request: &T,
) -> Result<String, GuiChatClientError> {
    let body = serde_json::to_string(request)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("serialize: {e}")))?;
    let sidecar = read_sidecar(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("sidecar: {e}")))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(GuiChatClientError::PreWriteUnavailable(
            "stale audit-RPC sidecar".into(),
        ));
    }
    let token = read_rpc_token(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("token: {e}")))?;
    let wire = format!(
        "POST {path} HTTP/1.1\r\nHost: neoth-local\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = tokio::time::timeout(
        RPC_EXCHANGE_TIMEOUT,
        super::transport::connect(&sidecar.endpoint),
    )
    .await
    .map_err(|_| GuiChatClientError::PreWriteUnavailable("connect deadline".into()))
    .and_then(|r| {
        r.map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("connect: {e}")))
    })?;
    let (status, raw) = tokio::time::timeout(super::CHAT_TURN_RESPONSE_TIMEOUT, async {
        stream
            .write_all(wire.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        read_rpc_response_with_limit(
            &mut stream,
            super::DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES.saturating_add(4096),
        )
        .await
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| GuiChatClientError::Indeterminate("GUI response deadline".into()))?
    .map_err(GuiChatClientError::Indeterminate)?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .ok_or_else(|| GuiChatClientError::Indeterminate("missing response boundary".into()))?;
    if status != 200 {
        return Err(GuiChatClientError::Refused(status, body));
    }
    Ok(body)
}
/// Held GUI attach transport. It writes once, then verifies and delivers each
/// close-delimited NDJSON frame. Any later fault is indeterminate and cannot
/// cause a provider retry.
pub(crate) async fn gui_chat_attach(
    home: &Path,
    request: &crate::daemon::gui_chat_protocol::GuiChatAttachRequest,
    on_frame: &mut (
             dyn FnMut(
        crate::daemon::gui_chat_protocol::GuiChatStreamFrame,
    ) -> Result<(), GuiChatClientError>
                 + Send
         ),
) -> Result<(), GuiChatClientError> {
    let body = serde_json::to_string(request)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("serialize attach: {e}")))?;
    let sidecar = read_sidecar(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("sidecar: {e}")))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(GuiChatClientError::PreWriteUnavailable(
            "stale audit-RPC sidecar".into(),
        ));
    }
    let token = read_rpc_token(home)
        .map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("token: {e}")))?;
    let wire = format!(
        "POST {} HTTP/1.1\r\nHost: neoth-local\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        crate::daemon::gui_chat_protocol::GUI_CHAT_V1_ATTACH_PATH,
        body.len()
    );
    let mut stream = tokio::time::timeout(
        RPC_EXCHANGE_TIMEOUT,
        super::transport::connect(&sidecar.endpoint),
    )
    .await
    .map_err(|_| GuiChatClientError::PreWriteUnavailable("attach connect deadline".into()))
    .and_then(|r| {
        r.map_err(|e| GuiChatClientError::PreWriteUnavailable(format!("attach connect: {e}")))
    })?;
    stream
        .write_all(wire.as_bytes())
        .await
        .map_err(|e| GuiChatClientError::Indeterminate(format!("attach write: {e}")))?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header = false;
    let mut expected = request.after_sequence.saturating_add(1);
    loop {
        let read_timeout = if header {
            crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT + GUI_CHAT_ATTACH_TERMINAL_MARGIN
        } else {
            RPC_EXCHANGE_TIMEOUT
        };
        let n = tokio::time::timeout(read_timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| GuiChatClientError::Indeterminate("attach frame deadline".into()))?
            .map_err(|e| GuiChatClientError::Indeterminate(format!("attach read: {e}")))?;
        if n == 0 {
            return Err(GuiChatClientError::Indeterminate(
                "attach EOF before terminal".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..n]);
        if !header {
            let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                if bytes.len() > 8192 {
                    return Err(GuiChatClientError::Indeterminate(
                        "attach headers too large".into(),
                    ));
                };
                continue;
            };
            let head = std::str::from_utf8(&bytes[..pos])
                .map_err(|_| GuiChatClientError::Indeterminate("attach headers utf8".into()))?;
            let mut lines = head.split("\r\n");
            if lines.next() != Some("HTTP/1.1 200 OK") {
                return Err(GuiChatClientError::Indeterminate(
                    "attach refused after write".into(),
                ));
            }
            for line in lines {
                let (name, _) = line.split_once(':').ok_or_else(|| {
                    GuiChatClientError::Indeterminate("malformed attach header".into())
                })?;
                if name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                {
                    return Err(GuiChatClientError::Indeterminate(
                        "attach must be close-delimited NDJSON".into(),
                    ));
                }
            }
            bytes.drain(..pos + 4);
            header = true;
        }
        while let Some(pos) = bytes.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = bytes.drain(..=pos).collect();
            if line.len() > crate::daemon::gui_chat_protocol::GUI_CHAT_FRAME_MAX_BYTES {
                return Err(GuiChatClientError::Indeterminate(
                    "attach frame too large".into(),
                ));
            };
            let text = std::str::from_utf8(&line)
                .map_err(|_| GuiChatClientError::Indeterminate("attach frame utf8".into()))?
                .trim();
            if text.is_empty() {
                continue;
            };
            let frame: crate::daemon::gui_chat_protocol::GuiChatStreamFrame =
                serde_json::from_str(text).map_err(|_| {
                    GuiChatClientError::Indeterminate("malformed NDJSON frame".into())
                })?;
            crate::daemon::gui_chat_protocol::validate_stream_frame(&frame)
                .map_err(|r| GuiChatClientError::Indeterminate(r.to_string()))?;
            if frame.boot_id != request.expected_boot_id
                || frame.sequence != expected
                || frame.turn_id != request.turn_id
                || frame.subscription.session_id != request.session_id
                || frame.subscription.surface != request.surface
                || frame.subscription.generation != request.subscription_generation
            {
                return Err(GuiChatClientError::Indeterminate(
                    "attach rotation or sequence mismatch".into(),
                ));
            };
            expected = expected.saturating_add(1);
            let terminal = matches!(
                &frame.payload,
                crate::daemon::gui_chat_protocol::GuiChatFramePayload::Terminal { .. }
            );
            on_frame(frame)?;
            if terminal {
                return Ok(());
            }
        }
        if bytes.len() > crate::daemon::gui_chat_protocol::GUI_CHAT_FRAME_MAX_BYTES {
            return Err(GuiChatClientError::Indeterminate(
                "unterminated attach frame too large".into(),
            ));
        }
    }
}
/// Shared same-user IPC POST to the daemon's audit-RPC listener (same
/// sidecar + bearer-token auth + staleness guard as [`try_post_audit_frame`]).
/// Returns `(status, full_response)`. Used by the D34 FULL-AUTO token verbs.
async fn post_rpc(
    home: &Path,
    path: &str,
    body: &str,
) -> std::result::Result<(u16, String), AuditRpcClientError> {
    let sidecar =
        read_sidecar(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    if !exact_daemon_owner(home, sidecar.pid, &sidecar.endpoint_nonce) {
        return Err(AuditRpcClientError::Unavailable(format!(
            "stale audit-RPC sidecar (daemon pid {} does not own the endpoint)",
            sidecar.pid
        )));
    }
    let token =
        read_rpc_token(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: neoth-local\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    exchange_rpc(sidecar.endpoint, req).await
}

async fn exchange_rpc(
    endpoint: super::transport::AuditEndpointV2,
    request: String,
) -> std::result::Result<(u16, String), AuditRpcClientError> {
    let endpoint_label = format!("{endpoint:?}");
    tokio::time::timeout(RPC_EXCHANGE_TIMEOUT, async move {
        let mut stream = super::transport::connect(&endpoint)
            .await
            .map_err(|e| AuditRpcClientError::Unavailable(format!("connect {endpoint:?}: {e}")))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| AuditRpcClientError::Unavailable(format!("write: {e}")))?;
        read_rpc_response(&mut stream).await
    })
    .await
    .map_err(|_| {
        AuditRpcClientError::Unavailable(format!(
            "RPC exchange with {endpoint_label} exceeded the {}s deadline",
            RPC_EXCHANGE_TIMEOUT.as_secs()
        ))
    })?
}

async fn read_rpc_response(
    stream: &mut super::transport::AuditStream,
) -> std::result::Result<(u16, String), AuditRpcClientError> {
    read_rpc_response_with_limit(stream, MAX_RPC_RESPONSE_BYTES).await
}

async fn read_rpc_response_with_limit(
    stream: &mut super::transport::AuditStream,
    max_response_bytes: usize,
) -> std::result::Result<(u16, String), AuditRpcClientError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| AuditRpcClientError::Unavailable(format!("read: {error}")))?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > max_response_bytes {
            return Err(AuditRpcClientError::Unavailable(format!(
                "RPC response exceeds {max_response_bytes} byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    parse_rpc_response(bytes)
}

fn parse_rpc_response(bytes: Vec<u8>) -> std::result::Result<(u16, String), AuditRpcClientError> {
    let header_offset = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AuditRpcClientError::Unavailable("malformed RPC response".into()))?;
    let body_offset = header_offset + 4;
    let head = std::str::from_utf8(&bytes[..header_offset]).map_err(|error| {
        AuditRpcClientError::Unavailable(format!("invalid RPC headers: {error}"))
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(AuditRpcClientError::Unavailable(
            "RPC response did not use HTTP/1.1".into(),
        ));
    }
    let status = status_parts
        .next()
        .filter(|value| value.len() == 3)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| AuditRpcClientError::Unavailable("invalid RPC status code".into()))?;

    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            AuditRpcClientError::Unavailable("malformed RPC response header".into())
        })?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(AuditRpcClientError::Unavailable(
                "chunked RPC responses are not supported".into(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(AuditRpcClientError::Unavailable(
                    "duplicate RPC Content-Length".into(),
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                AuditRpcClientError::Unavailable("invalid RPC Content-Length".into())
            })?);
        }
    }
    let content_length = content_length
        .ok_or_else(|| AuditRpcClientError::Unavailable("missing RPC Content-Length".into()))?;
    if content_length > MAX_RPC_RESPONSE_BYTES.saturating_sub(body_offset)
        || bytes.len() != body_offset.saturating_add(content_length)
    {
        return Err(AuditRpcClientError::Unavailable(
            "RPC response body length mismatch".into(),
        ));
    }
    let response = String::from_utf8(bytes)
        .map_err(|error| AuditRpcClientError::Unavailable(format!("invalid RPC body: {error}")))?;
    Ok((status, response))
}

#[cfg(feature = "cluster")]
fn response_json<T: serde::de::DeserializeOwned>(
    status: u16,
    response: &str,
) -> std::result::Result<T, AuditRpcClientError> {
    if status != 200 {
        return Err(AuditRpcClientError::Refused(status));
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    serde_json::from_str(body)
        .map_err(|error| AuditRpcClientError::Unavailable(format!("invalid RPC JSON: {error}")))
}

#[cfg(feature = "cluster")]
pub async fn membership_snapshot(
    home: &Path,
) -> std::result::Result<crate::cluster::membership::MembershipSnapshotEnvelope, AuditRpcClientError>
{
    let (status, response) = post_rpc(home, "/membership/status", "{}").await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_runtime_health(
    home: &Path,
) -> std::result::Result<crate::cluster::membership::MembershipRuntimeHealth, AuditRpcClientError> {
    let (status, response) = post_rpc(home, "/membership/runtime-health", "{}").await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_set_task_delegate_assignment(
    home: &Path,
    request: &crate::cluster::membership::TaskDelegateAssignmentRequest,
) -> std::result::Result<
    crate::cluster::membership::TaskDelegateAssignmentCommitReceipt,
    AuditRpcClientError,
> {
    let body = serde_json::to_string(request)
        .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/task-delegate", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_set_task_delegate_scope_assignment(
    home: &Path,
    request: &crate::cluster::membership::TaskDelegateScopedAssignmentRequest,
) -> std::result::Result<
    crate::cluster::membership::TaskDelegateScopedAssignmentCommitReceipt,
    AuditRpcClientError,
> {
    let body = serde_json::to_string(request)
        .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/task-delegate/scope", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_set_task_delegate_outbound_assignment(
    home: &Path,
    request: &crate::cluster::membership::TaskDelegateOutboundAssignmentRequest,
) -> std::result::Result<
    crate::cluster::membership::TaskDelegateOutboundAssignmentCommitReceipt,
    AuditRpcClientError,
> {
    let body = serde_json::to_string(request)
        .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) =
        post_rpc(home, "/membership/task-delegate/outbound-assignment", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn dispatch_task_delegate_outbound(
    home: &Path,
    request: &crate::cluster::runtime_supervisor::OutboundTaskDelegateDispatchRequest,
) -> std::result::Result<
    crate::cluster::runtime_supervisor::OutboundTaskDelegateDispatchReceipt,
    AuditRpcClientError,
> {
    let body = serde_json::to_string(request)
        .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/task-delegate/outbound", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_revoke(
    home: &Path,
    request: &crate::cluster::membership::MembershipRevokeRequest,
) -> std::result::Result<crate::cluster::membership::RevokeReceipt, AuditRpcClientError> {
    let body = serde_json::to_string(request)
        .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/revoke", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_revocation_status(
    home: &Path,
    request_id: &str,
) -> std::result::Result<
    Option<crate::cluster::membership::RevocationIntentStatus>,
    AuditRpcClientError,
> {
    let body = serde_json::json!({ "request_id": request_id }).to_string();
    let (status, response) = post_rpc(home, "/membership/revoke/status", &body).await?;
    response_json(status, &response)
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "cluster")]
pub async fn membership_invite(
    home: &Path,
    stable_node_id: &crate::cluster::membership::StableNodeId,
    signing_public_key: &[u8; 32],
    carrier: crate::cluster::membership::CarrierKind,
    transport_identity: &crate::cluster::membership::TransportIdentity,
    endpoint: &str,
    label: &str,
    _now_unix: i64,
    expires_at_unix: i64,
) -> std::result::Result<crate::cluster::membership::EnrollmentInvite, AuditRpcClientError> {
    let body = serde_json::to_string(&crate::cluster::membership::MembershipInviteRequest {
        stable_node_id: stable_node_id.clone(),
        signing_public_key_hex: hex::encode(signing_public_key),
        carrier,
        transport_identity: transport_identity.clone(),
        endpoint: endpoint.to_string(),
        label: label.to_string(),
        expires_at_unix,
    })
    .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/invite", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_confirm(
    home: &Path,
    invite_id: &str,
    attestation: &crate::cluster::membership::EndpointAttestation,
    carrier: crate::cluster::membership::CarrierKind,
    authenticated_transport: &crate::cluster::membership::TransportIdentity,
    endpoint: &str,
    _now_unix: i64,
) -> std::result::Result<crate::cluster::membership::EnrollmentReceipt, AuditRpcClientError> {
    let body = serde_json::to_string(&crate::cluster::membership::MembershipConfirmRequest {
        invite_id: invite_id.to_string(),
        attestation: attestation.clone(),
        carrier,
        authenticated_transport: authenticated_transport.clone(),
        endpoint: endpoint.to_string(),
    })
    .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/confirm", &body).await?;
    response_json(status, &response)
}

#[cfg(feature = "cluster")]
pub async fn membership_legacy_pending(
    home: &Path,
    carrier: crate::cluster::membership::CarrierKind,
    transport_identity: &crate::cluster::membership::TransportIdentity,
    endpoint: &str,
    label: &str,
) -> std::result::Result<crate::cluster::membership::StableNodeId, AuditRpcClientError> {
    let body = serde_json::to_string(
        &crate::cluster::membership::MembershipLegacyPendingRequest {
            carrier,
            transport_identity: transport_identity.clone(),
            endpoint: endpoint.to_string(),
            label: label.to_string(),
        },
    )
    .map_err(|error| AuditRpcClientError::Unavailable(error.to_string()))?;
    let (status, response) = post_rpc(home, "/membership/legacy-pending", &body).await?;
    response_json(status, &response)
}

/// GR-RESID-D34 — ask the running daemon to mint a single-use, short-TTL
/// FULL-AUTO token. The GUI calls this AFTER its two-step confirm dialog passes,
/// then spawns `neoth autonomy full-auto --gui-confirmed --gui-token <t>`.
/// Returns the token, or `None` if the daemon is unreachable / refuses / the
/// response carries no token.
pub async fn mint_fullauto_token(home: &Path) -> Option<String> {
    let (status, resp) = post_rpc(home, "/fullauto-token/mint", "{}").await.ok()?;
    if status != 200 {
        return None;
    }
    // The JSON body follows the blank header/body separator.
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("token")?
        .as_str()
        .map(str::to_string)
}

/// GR-RESID-D34 — validate + CONSUME a FULL-AUTO token at the daemon (the CLI
/// calls this when `--gui-token` is present). `true` iff the daemon confirmed it
/// (HTTP 200, single-use). Any failure (unreachable / expired / wrong / already
/// consumed) → `false`, and the FULL-AUTO bypass is then denied.
pub async fn consume_fullauto_token(home: &Path, token: &str) -> bool {
    let body = format!("{{\"token\":{token:?}}}");
    matches!(
        post_rpc(home, "/fullauto-token/consume", &body).await,
        Ok((200, _))
    )
}

/// Mint a daemon-held, short-lived approval token for one exact GUI
/// `jobs --run` request binding. The daemon appends the mandatory approval
/// audit before returning the token. `None` means the daemon/audit writer is
/// unavailable, refused the request, or returned a malformed response.
pub async fn mint_jobs_run_token(home: &Path, request_binding_sha256: &str) -> Option<String> {
    let body = serde_json::json!({
        "request_binding_sha256": request_binding_sha256,
    })
    .to_string();
    let (status, resp) = post_rpc(home, "/jobs-run-token/mint", &body).await.ok()?;
    if status != 200 {
        return None;
    }
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("token")?
        .as_str()
        .map(str::to_string)
}

/// Validate and consume a GUI jobs-run token against the exact request digest.
/// Any mismatch, replay, expiry, or daemon failure is a fail-closed `false`.
pub async fn consume_jobs_run_token(
    home: &Path,
    token: &str,
    request_binding_sha256: &str,
) -> bool {
    let body = serde_json::json!({
        "token": token,
        "request_binding_sha256": request_binding_sha256,
    })
    .to_string();
    matches!(
        post_rpc(home, "/jobs-run-token/consume", &body).await,
        Ok((200, _))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(headers: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\n{headers}\r\n\r\n{body}").into_bytes()
    }

    fn health_response(status: u16, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn rpc_response_requires_one_exact_content_length() {
        let (status, parsed) =
            parse_rpc_response(response("Content-Length: 2", "{}")).expect("valid response");
        assert_eq!(status, 200);
        assert!(parsed.ends_with("\r\n\r\n{}"));

        for malformed in [
            response("Content-Type: application/json", "{}"),
            response("Content-Length: nope", "{}"),
            response("Content-Length: 2\r\nContent-Length: 2", "{}"),
            response("Transfer-Encoding: chunked", "{}"),
            response("Content-Length: 3", "{}"),
            response("Content-Length: 1", "{}"),
        ] {
            assert!(parse_rpc_response(malformed).is_err());
        }
    }

    #[test]
    fn rpc_response_rejects_malformed_status_and_headers() {
        for malformed in [
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 nope OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nnot-a-header\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}".to_vec(),
        ] {
            assert!(parse_rpc_response(malformed).is_err());
        }
    }

    #[test]
    fn health_response_diagnostics_distinguish_status_body_and_transport_rejections() {
        assert_eq!(
            validate_health_response(health_response(503, "{\"ok\":true}")),
            Err(AuditRpcHealthError::Status(503))
        );
        assert_eq!(
            validate_health_response(health_response(200, "{\"ok\":false}")),
            Err(AuditRpcHealthError::Body {
                bytes: "{\"ok\":false}".len()
            })
        );
        assert!(matches!(
            validate_health_response(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            Err(AuditRpcHealthError::TransportOrPeer(_))
        ));
    }

    #[test]
    fn health_check_diagnostics_distinguish_sidecar_owner_and_token_rejections() {
        let home = tempfile::tempdir().expect("create health-check home");
        assert!(matches!(
            health_check(home.path()),
            Err(AuditRpcHealthError::Sidecar(_))
        ));

        // Exercise the strict nonce/owner path with a fresh value: even test
        // sidecars must not normalize a reusable endpoint capability.
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let endpoint = super::super::transport::endpoint_for_home(home.path(), &nonce)
            .expect("derive health-check endpoint");
        super::super::sidecar::write_sidecar(home.path(), &endpoint, std::process::id(), &nonce)
            .expect("write strict health-check sidecar");
        assert_eq!(
            health_check(home.path()),
            Err(AuditRpcHealthError::ExactDaemonOwner {
                pid: std::process::id()
            })
        );

        let mut daemon = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("acquire daemon PID lock");
        daemon
            .publish_endpoint_nonce(&nonce)
            .expect("publish exact endpoint nonce");
        assert!(matches!(
            health_check(home.path()),
            Err(AuditRpcHealthError::Token(_))
        ));
    }

    #[test]
    fn health_check_bounds_the_full_exchange_to_one_second() {
        assert_eq!(
            HEALTH_CHECK_EXCHANGE_TIMEOUT,
            std::time::Duration::from_secs(1)
        );
    }

    #[test]
    fn instance_commitment_is_stable_for_one_nonce_and_changes_with_the_boot_nonce() {
        let first = instance_commitment_for_nonce("first-test-boot-nonce");
        assert_eq!(
            first,
            instance_commitment_for_nonce("first-test-boot-nonce")
        );
        assert_ne!(
            first,
            instance_commitment_for_nonce("second-test-boot-nonce")
        );
        assert_eq!(first.0.len(), 64);
        assert!(first.0.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
