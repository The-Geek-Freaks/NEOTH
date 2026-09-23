//! AUDIT-RPC-01 — same-user OS audit-RPC listener + client.
//!
//! ## Why this exists
//! The daemon owns the SINGLE WAL writer (the single-writer invariant). So when
//! `neoth serve` is running, a one-shot CLI (`neoth os launch`, `fs read/write`,
//! `autonomy set`, `lease …`) cannot open a second writer to record its own
//! gated action — it passes `writer: None` and the action runs gated but
//! UN-audited. This module closes that gap: the one-shot CLI forwards an *audit
//! intent* to the running daemon over an OS-authenticated same-user IPC
//! transport, and the daemon (which owns the writer) appends the frame on its
//! behalf.
//!
//! ## Security model — anti-audit-poisoning
//! The audit chain is NEOTH's verifiable-loyalty wedge, so a forged frame is a
//! real threat. Defenses, all fail-closed:
//!   1. **Kernel-attested same user.** Unix uses an owner-private Unix socket
//!      plus peer-credential UID equality. Windows uses a current-TokenUser
//!      DACL, local-only first-instance named pipe and post-connect client SID
//!      equality. There is no TCP fallback.
//!   2. **Per-boot bearer token.** 32 bytes from the OS CSPRNG, base64url, freshly
//!      minted on every daemon start (a token captured before a restart is dead
//!      after it), written `0600` on unix / DPAPI-wrapped+DACL on Windows via the
//!      same `write_key_securely` path as the WAL HMAC key. Only a SAME-UID
//!      process can read it. Checked constant-time; 5-strike cooldown on failure.
//!   3. **Compile-time event-type allowlist.** Only the one-shot-emittable
//!      permission-band codes are acceptable over IPC; anything else
//!      (daemon-lifecycle, cluster, quota, …) is refused 422. The allowlist is a
//!      `const` — not operator-tunable, since an operator who could widen it
//!      could already forge frames directly.
//!   4. **Body cap** 4096 bytes (audit payloads are small structured JSON).
//!
//! A process running as the same OS user can read the defense-in-depth bearer
//! and submit allowlisted frames; that user already owns the NEOTH instance and
//! WAL keys. A different local user cannot reach the application codec.
//!
//! The approval-token endpoints use that same operator-authority boundary. A
//! jobs-run token is bound to one canonical request digest, expires quickly,
//! and is consumed once. Its CLI mint path re-reads the live autonomy policy
//! and cannot override a static `Deny`; the daemon also appends a mandatory WAL
//! proof before it releases the token. This is deliberately not an OS sandbox
//! against the operator who owns both `freedom.yaml` and the RPC credential.
//!
//! The internal listener is mandatory while `neoth serve` owns the WAL.
//! `freedom.yaml::audit_rpc.enabled` controls only the optional public audit and
//! approval-token routes; the Skill-mutation and durable TrustDecision
//! authority routes remain available.
//! The listener is spawned from `cli/serve.rs` and aborted on shutdown; the
//! sidecar is removed by [`SidecarGuard`] on drop.
//!
//! ## Module layout (the file was split once it crossed ~800 LOC)
//!   - [`token`]   — the per-boot bearer secret (mint / read / path).
//!   - [`sidecar`] — typed local-endpoint discovery + stale guard + `SidecarGuard`.
//!   - [`transport`] — Unix-socket / Windows named-pipe bind, peer proof, connect.
//!   - [`server`]  — the daemon listener: bind, accept, auth, allowlist, append.
//!   - [`client`]  — the one-shot CLI side: reachability, required-audit gate,
//!                   `try_post_audit_frame`.
//!
//! Every public item keeps its previous `crate::daemon::audit_rpc::<name>` path
//! via the re-exports below, so the split is internal-only.

mod client;
mod fullauto_token;
mod server;
mod sidecar;
mod token;
mod transport;

#[cfg(test)]
mod tests;

pub(crate) use client::try_daemon_plain_chat_turn;
pub(crate) use client::try_post_skill_mutation_frame;
pub(crate) use client::try_post_trust_decision_once;
#[cfg(any(unix, windows))]
pub(crate) use client::verified_daemon_endpoint_nonce;
pub use client::{
    AuditRpcClientError, consume_fullauto_token, consume_jobs_run_token, enforce_required_audit,
    is_reachable, mint_fullauto_token, mint_jobs_run_token, try_post_audit_frame,
    try_post_audit_frame_with_subtype,
};
pub(crate) use client::{
    DaemonInstanceProof, InstanceCommitment, authenticated_live_instance,
    instance_commitment_for_nonce,
};
pub(crate) use client::{
    GuiChatClientError, attested_gui_chat_boot_id, gui_chat_attach, gui_chat_post,
};
#[cfg(feature = "cluster")]
pub use client::{
    dispatch_task_delegate_outbound, membership_confirm, membership_invite,
    membership_legacy_pending, membership_revocation_status, membership_revoke,
    membership_runtime_health, membership_set_task_delegate_assignment, membership_snapshot,
};
pub use fullauto_token::{FULLAUTO_TOKEN_TTL, FullAutoTokenStore, JOBS_RUN_TOKEN_TTL};
pub(crate) use server::bind_and_serve;
pub use server::{
    ALLOWED_CLIENT_EVENT_TYPES, ALLOWED_CLIENT_EXTENDED_SUBTYPES, AuditRpcState,
    is_allowed_client_event, is_allowed_client_event_pair,
};
#[cfg(test)]
pub(crate) use sidecar::read_sidecar;
pub(crate) use sidecar::write_sidecar;
pub use sidecar::{SidecarGuard, remove_sidecar, sidecar_path};
pub use token::{init_rpc_token, read_rpc_token, rpc_token_path};
#[cfg(test)]
pub(crate) use transport::AuditEndpointV2;
pub(crate) use transport::AuditStream;
#[cfg(test)]
pub(crate) use transport::endpoint_for_home;
pub(crate) use transport::homes_same_identity;

/// W39's sealed same-user chat contract.  It deliberately carries only one
/// ordinary plaintext message; all configuration, provider, consent, WAL and
/// parser custody remains daemon-owned.
pub(crate) const DAEMON_PLAIN_CHAT_SCHEMA_VERSION: u8 = 1;
/// Each byte may need a six-byte JSON escape.  Keep the UTF-8 message cap
/// inside the inherited 4-KiB body cap even for an all-control-byte message.
pub(crate) const DAEMON_PLAIN_CHAT_MESSAGE_MAX_BYTES: usize = 640;
pub(crate) const DAEMON_PLAIN_CHAT_TRANSPORT_BODY_MAX_BYTES: usize = 4 * 1024;
pub(crate) const DAEMON_PLAIN_CHAT_MAX_RECORDS: usize = 64;
pub(crate) const DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES: usize = 64 * 1024;
const DAEMON_PLAIN_CHAT_RESPONSE_ID_BYTES: usize = 32;
const DAEMON_PLAIN_CHAT_SESSION_ID_MAX_BYTES: usize = 128;
pub(crate) const CHAT_TURN_RESPONSE_TIMEOUT: std::time::Duration =
    // This is a transport envelope, not a second provider-progress watchdog.
    // It leaves the core-owned 120-second silence timeout enough time to
    // reach the peer as its typed failed outcome.
    std::time::Duration::from_secs(125);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatRequest {
    pub(crate) schema_version: u8,
    pub(crate) message: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatResponse {
    pub(crate) records: Vec<DaemonPlainChatRecord>,
    pub(crate) terminal: DaemonPlainChatTerminal,
}

/// A post-admission daemon outcome. It is deliberately a non-200 response so
/// callers cannot turn a timed-out provider attempt into a success terminal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatErrorResponse {
    pub(crate) code: DaemonPlainChatErrorCode,
    pub(crate) timeout_seconds: u64,
    pub(crate) retryable: bool,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DaemonPlainChatErrorCode {
    TurnSilenceTimeout,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatRecord {
    pub(crate) kind: DaemonPlainChatRecordKind,
    pub(crate) text: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DaemonPlainChatRecordKind {
    Stdout,
    Stderr,
    Notice,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatTerminal {
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) session_id: Option<String>,
    #[serde(default)]
    pub(crate) response_feedback: Option<DaemonPlainChatResponseFeedbackTarget>,
    #[serde(default)]
    pub(crate) response_feedback_unavailable: bool,
}

/// Opaque terminal-issued feedback capability. This wire form transports only
/// the producer-issued id, its exact session binding, and its revision.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonPlainChatResponseFeedbackTarget {
    pub(crate) response_id: String,
    pub(crate) session_id: String,
    pub(crate) revision: u64,
}

pub(crate) fn validate_daemon_plain_chat_request(
    request: &DaemonPlainChatRequest,
) -> std::result::Result<(), &'static str> {
    if request.schema_version != DAEMON_PLAIN_CHAT_SCHEMA_VERSION {
        return Err("unsupported_chat_schema_version");
    }
    if request.message.is_empty() {
        return Err("chat_message_empty");
    }
    if !is_daemon_plain_chat_message(&request.message) {
        return Err("chat_local_action_not_allowed");
    }
    if request.message.len() > DAEMON_PLAIN_CHAT_MESSAGE_MAX_BYTES {
        return Err("chat_message_too_large");
    }
    Ok(())
}

/// Slash forms are pre-runtime local actions in direct CLI chat. A same-user
/// peer cannot use the sealed daemon message field to bypass that boundary.
/// Leading whitespace is ignored only for identifying a command; ordinary
/// text retains its original bytes and remains eligible.
pub(crate) fn is_daemon_plain_chat_message(message: &str) -> bool {
    !message.trim_start().starts_with('/')
}

pub(crate) fn validate_daemon_plain_chat_response(
    response: &DaemonPlainChatResponse,
    encoded_len: usize,
) -> std::result::Result<(), &'static str> {
    if response.records.len() > DAEMON_PLAIN_CHAT_MAX_RECORDS {
        return Err("chat_response_too_many_records");
    }
    if encoded_len > DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES {
        return Err("chat_response_too_large");
    }
    let terminal = &response.terminal;
    if terminal.response_feedback.is_some() && terminal.response_feedback_unavailable {
        return Err("chat_response_feedback_conflicting_availability");
    }
    if let Some(target) = terminal.response_feedback.as_ref() {
        if target.response_id.len() != DAEMON_PLAIN_CHAT_RESPONSE_ID_BYTES
            || !target
                .response_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("chat_response_feedback_id_invalid");
        }
        if target.session_id.is_empty()
            || target.session_id.len() > DAEMON_PLAIN_CHAT_SESSION_ID_MAX_BYTES
        {
            return Err("chat_response_feedback_session_invalid");
        }
        if terminal.session_id.as_deref() != Some(target.session_id.as_str()) {
            return Err("chat_response_feedback_session_mismatch");
        }
    }
    Ok(())
}

pub(crate) fn validate_daemon_plain_chat_error_response(
    response: &DaemonPlainChatErrorResponse,
) -> std::result::Result<(), &'static str> {
    match response.code {
        DaemonPlainChatErrorCode::TurnSilenceTimeout
            if response.timeout_seconds
                == crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT.as_secs()
                && response.retryable =>
        {
            Ok(())
        }
        DaemonPlainChatErrorCode::TurnSilenceTimeout => {
            Err("chat_turn_silence_timeout_fields_invalid")
        }
    }
}

/// Closed same-user transport for a descriptor already resolved by Gate and
/// durably retained by its caller. This carries no raw action/body/recipient
/// and never resolves policy on the caller's behalf.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustDecisionOnceRequest {
    schema_version: u8,
    descriptor: crate::permissions::trust_ledger::TrustAdmissionDescriptor,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustDecisionOnceResponse {
    schema_version: u8,
    outcome: TrustDecisionOnceWireOutcome,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TrustDecisionOnceWireOutcome {
    ExistingExact,
    AppendedExact,
}

#[cfg(test)]
mod daemon_plain_chat_contract_tests {
    use super::*;

    fn request(message: String) -> DaemonPlainChatRequest {
        DaemonPlainChatRequest {
            schema_version: DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
            message,
        }
    }

    #[test]
    fn sealed_request_rejects_unknown_fields_and_invalid_message_bounds() {
        assert!(
            serde_json::from_str::<DaemonPlainChatRequest>(
                r#"{"schema_version":1,"message":"hello","config":"forbidden"}"#
            )
            .is_err()
        );
        assert_eq!(
            validate_daemon_plain_chat_request(&request(String::new())),
            Err("chat_message_empty")
        );
        assert_eq!(
            validate_daemon_plain_chat_request(&request(
                "x".repeat(DAEMON_PLAIN_CHAT_MESSAGE_MAX_BYTES + 1)
            )),
            Err("chat_message_too_large")
        );
        assert_eq!(
            validate_daemon_plain_chat_request(&DaemonPlainChatRequest {
                schema_version: DAEMON_PLAIN_CHAT_SCHEMA_VERSION + 1,
                message: "hello".into(),
            }),
            Err("unsupported_chat_schema_version")
        );
        for message in ["/help", " \t /skill-from-doc no", "\n /any-local-action"] {
            assert_eq!(
                validate_daemon_plain_chat_request(&request(message.into())),
                Err("chat_local_action_not_allowed"),
                "sealed daemon ingress must reject every local slash form"
            );
        }
        assert!(is_daemon_plain_chat_message("  ordinary text"));
        assert!(is_daemon_plain_chat_message("\n\tordinary text"));
    }

    #[test]
    fn sealed_response_rejects_unknown_shape_and_declared_bounds() {
        let legacy = serde_json::from_str::<DaemonPlainChatResponse>(
            r#"{"records":[],"terminal":{"provider":"p","model":"m","session_id":null}}"#,
        )
        .expect("older sealed terminal shape remains readable without feedback fields");
        assert_eq!(legacy.terminal.response_feedback, None);
        assert!(!legacy.terminal.response_feedback_unavailable);
        assert!(serde_json::from_str::<DaemonPlainChatResponse>(
            r#"{"records":[],"terminal":{"provider":"p","model":"m","session_id":null,"extra":true}}"#
        )
        .is_err());
        let response = DaemonPlainChatResponse {
            records: (0..=DAEMON_PLAIN_CHAT_MAX_RECORDS)
                .map(|_| DaemonPlainChatRecord {
                    kind: DaemonPlainChatRecordKind::Stdout,
                    text: "x".into(),
                })
                .collect(),
            terminal: DaemonPlainChatTerminal {
                provider: "provider".into(),
                model: "model".into(),
                session_id: None,
                response_feedback: None,
                response_feedback_unavailable: false,
            },
        };
        assert_eq!(
            validate_daemon_plain_chat_response(&response, 1),
            Err("chat_response_too_many_records")
        );
        let response = DaemonPlainChatResponse {
            records: Vec::new(),
            terminal: response.terminal,
        };
        assert_eq!(
            validate_daemon_plain_chat_response(
                &response,
                DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES + 1,
            ),
            Err("chat_response_too_large")
        );
    }

    #[test]
    fn sealed_response_feedback_target_requires_exact_terminal_session() {
        let mut response = DaemonPlainChatResponse {
            records: Vec::new(),
            terminal: DaemonPlainChatTerminal {
                provider: "provider".into(),
                model: "model".into(),
                session_id: Some("terminal-session".into()),
                response_feedback: Some(DaemonPlainChatResponseFeedbackTarget {
                    response_id: "a".repeat(DAEMON_PLAIN_CHAT_RESPONSE_ID_BYTES),
                    session_id: "terminal-session".into(),
                    revision: 0,
                }),
                response_feedback_unavailable: false,
            },
        };
        assert_eq!(validate_daemon_plain_chat_response(&response, 0), Ok(()));
        response.terminal.response_feedback_unavailable = true;
        assert_eq!(
            validate_daemon_plain_chat_response(&response, 0),
            Err("chat_response_feedback_conflicting_availability")
        );
        response.terminal.response_feedback_unavailable = false;
        response
            .terminal
            .response_feedback
            .as_mut()
            .expect("target remains present")
            .response_id = "invalid".into();
        assert_eq!(
            validate_daemon_plain_chat_response(&response, 0),
            Err("chat_response_feedback_id_invalid")
        );
        response
            .terminal
            .response_feedback
            .as_mut()
            .expect("target remains present")
            .response_id = "a".repeat(DAEMON_PLAIN_CHAT_RESPONSE_ID_BYTES);
        response
            .terminal
            .response_feedback
            .as_mut()
            .expect("target remains present")
            .session_id = "other-session".into();
        assert_eq!(
            validate_daemon_plain_chat_response(&response, 0),
            Err("chat_response_feedback_session_mismatch")
        );
    }

    #[test]
    fn silence_timeout_error_is_typed_retry_guidance_not_a_success_response() {
        let response = DaemonPlainChatErrorResponse {
            code: DaemonPlainChatErrorCode::TurnSilenceTimeout,
            timeout_seconds: crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT.as_secs(),
            retryable: true,
        };
        assert_eq!(validate_daemon_plain_chat_error_response(&response), Ok(()));
        let encoded = serde_json::to_string(&response).expect("encode typed silence timeout");
        assert!(encoded.contains("turn_silence_timeout"));
        assert!(encoded.contains("retryable"));
        assert!(!encoded.contains("terminal"));

        let invalid = DaemonPlainChatErrorResponse {
            retryable: false,
            ..response
        };
        assert_eq!(
            validate_daemon_plain_chat_error_response(&invalid),
            Err("chat_turn_silence_timeout_fields_invalid")
        );
    }

    #[test]
    fn only_proven_prewrite_unavailability_allows_standalone_fallback() {
        assert!(
            client::DaemonPlainChatClientError::PreWriteUnavailable("no daemon".into())
                .allows_standalone_fallback()
        );
        for error in [
            client::DaemonPlainChatClientError::Refused(503),
            client::DaemonPlainChatClientError::Indeterminate("write failure".into()),
            client::DaemonPlainChatClientError::Indeterminate("EOF after write".into()),
            client::DaemonPlainChatClientError::Indeterminate("chat deadline".into()),
            client::DaemonPlainChatClientError::Indeterminate("malformed reply".into()),
        ] {
            assert!(
                !error.allows_standalone_fallback(),
                "post-write or daemon refusal must never launch a local turn: {error}"
            );
        }
    }
}
