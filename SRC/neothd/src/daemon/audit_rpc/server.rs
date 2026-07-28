//! AUDIT-RPC-01 — the daemon-side loopback listener.
//!
//! Binds `127.0.0.1:0`, accepts same-uid one-shot CLIs, and (after the
//! loopback-peer guard + bearer auth + compile-time event-type allowlist)
//! appends the forwarded frame into the daemon's single WAL writer, recording a
//! `0xAE AUDIT_RPC_ACCEPT` / `0xAF AUDIT_RPC_REJECT` marker. See the module-level
//! doc in `mod.rs` for the full security model.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::n8n_api::auth::AuthCooldown;
use crate::n8n_api::{constant_time_token_eq, extract_bearer_token};
use crate::wal::events::{
    EVENT_TYPE_AUDIT_RPC_ACCEPT, EVENT_TYPE_AUDIT_RPC_REJECT, EVENT_TYPE_EXTENDED,
    EVENT_TYPE_PERMISSION_GRANTED, ExtendedSubtype,
};
use crate::wal::writer::WalWriterHandle;

/// The ONLY event types a one-shot CLI may forward over the audit-RPC channel —
/// the permission-band codes that are lost today when the daemon owns the
/// writer: autonomy-level changes (`neoth autonomy set`), lease
/// grant/expire/revoke, and OS file read/write + app-launch (with their denial
/// variants). A compile-time `const`, deliberately NOT a config toggle:
/// widening it is a code change that goes through review, never a runtime flag
/// an attacker (or a careless operator) could flip.
pub const ALLOWED_CLIENT_EVENT_TYPES: &[u8] = &[
    0x2C, // INGEST_EXTRACTED       — `neoth ingest` extracted an asset
    0x2D, // EMBED_PERSISTED        — `neoth ingest` persisted an embedding
    0x30, // EMAIL_INGRESS_QUARANTINED — `neoth email fetch` withheld a mail body
    0x31, // EMAIL_TIEBREAK_APPLIED — `neoth email fetch` LLM-tie-broke a mail
    0x3D, // EMAIL_INGRESS_TRIAGED  — `neoth email fetch` triaged an inbound mail
    0x3E, // EVAL_CRITICAL_DIVERGENCE — `neoth recall-score` flagged a CRITICAL query
    0x65, // CONSENT_DECISION       — interactive allow-once/always/deny choice
    0x9B, // IDENTITY_MERGED        — `neoth identity merge` folded two identities
    0xC8, // TODO_WRITE             — `neoth todo add/close` mutated an external task list
    0xCA, // CALENDAR_WRITE         — `neoth calendar add` wrote an external calendar event
    0xCB, // CALENDAR_WRITE_DENIED  — `neoth calendar add` refused (writes_enabled off)
    0xA0, // PERMISSION_GRANTED — one-shot canonical permission gate decision
    0xA1, // PERMISSION_DENIED  — one-shot canonical permission gate decision
    0xA2, // LEVEL_ELEVATED   — `neoth autonomy set` raised the level
    0xA3, // LEVEL_DEROGATED  — `neoth autonomy set` lowered the level
    0xA5, // LEASE_GRANTED
    0xA6, // LEASE_EXPIRED
    0xA7, // LEASE_REVOKED
    0xA8, // OS_FILE_READ
    0xA9, // OS_FILE_DENIED
    0xAA, // OS_FILE_WRITE
    0xAB, // OS_FILE_WRITE_DENIED
    0xAC, // OS_APP_LAUNCH
    0xAD, // OS_APP_LAUNCH_DENIED
    0xD2, // SELF_UPDATE_APPLIED    — `neoth update --apply` replaced the binary
    0xD7, // MODEL_DOWNLOAD_START   — `neoth model pull` began a fetch
    0xD8, // MODEL_DOWNLOAD_COMPLETE — `neoth model pull` finished a fetch
    0xD9, // HMAC_KEY_ROTATED       — security rewrap / keys rotate boundary
    0xDA, // PRESET_APPLIED         — `neoth preset apply` merged a preset into freedom.yaml
    0xDB, // CONSENT_GRANTED        — `neoth consent grant` wrote a cloud-provider consent marker
    0xDC, // CONSENT_REVOKED        — `neoth consent revoke` removed a consent marker
    0xDD, // SUDOMODE_PRESET_APPLIED — FULL-AUTO config transaction phase
    0x54, // RISK_CONFIRM_GRANTED   — `neoth risk-confirm` granted a risk-override lease
    0xF5, // MEMORY_TRANSFER_EXPORTED — `neoth transfer export` sealed a bundle
    0xF6, // RECON_RUN              — `neoth recon uncover/tlsx` ran a gated recon tool
];

/// The ONLY EXTENDED subtypes accepted from one-shot clients. This list is
/// intentionally separate from the top-level allowlist so `(0x00, 0)` and a
/// non-zero subtype attached to any top-level event are both rejected.
pub const ALLOWED_CLIENT_EXTENDED_SUBTYPES: &[u8] = &[
    ExtendedSubtype::ProofKeyRotated as u8,
    ExtendedSubtype::ExternalHttpIntent as u8,
    ExtendedSubtype::ExternalHttpResult as u8,
    ExtendedSubtype::CommunicationProfileControlled as u8,
    ExtendedSubtype::PluginRemovalIntent as u8,
    ExtendedSubtype::PluginRemovalResult as u8,
    ExtendedSubtype::SkillInstallIntent as u8,
    ExtendedSubtype::SkillInstallResult as u8,
];

/// Max inbound request size (headers + body). Audit payloads are small.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Max body size accepted (tighter than the request cap).
const MAX_BODY_BYTES: usize = 4096;
/// Per-connection wall-clock budget. A client that opens a connection and then
/// stalls (slowloris) is dropped after this — bounds resource pinning.
const CONNECTION_TIMEOUT_SECS: u64 = 5;
/// Cap on concurrent in-flight connections. A local process can't exhaust the
/// daemon's FD table / task pool by holding connections open — excess
/// connections are dropped immediately (the one-shot falls back to its
/// un-audited path, fail-open on availability).
const MAX_CONCURRENT_CONNS: usize = 32;

/// `true` iff `event_type` may be forwarded by a one-shot CLI.
pub fn is_allowed_client_event(event_type: u8) -> bool {
    ALLOWED_CLIENT_EVENT_TYPES.contains(&event_type)
}

/// Strict event identity gate for the subtype-aware protocol. Existing clients
/// omit `event_subtype` and therefore decode as zero, preserving their exact
/// top-level behavior.
pub fn is_allowed_client_event_pair(event_type: u8, event_subtype: u8) -> bool {
    if event_type == EVENT_TYPE_EXTENDED {
        event_subtype != 0 && ALLOWED_CLIENT_EXTENDED_SUBTYPES.contains(&event_subtype)
    } else {
        event_subtype == 0 && is_allowed_client_event(event_type)
    }
}

/// Spawn-time state for the audit-RPC listener.
#[derive(Clone)]
pub struct AuditRpcState {
    pub token: String,
    pub writer: WalWriterHandle,
    pub cooldown: Arc<AuthCooldown>,
    /// Single-use, short-TTL approval tokens. Shared so FULL-AUTO and
    /// request-bound jobs-run mint/consume calls hit their respective slots in
    /// one daemon-owned store across separate connection tasks.
    pub fullauto: Arc<super::fullauto_token::FullAutoTokenStore>,
    /// Cluster authority is daemon-owned while `neoth serve` holds the PID
    /// lock. `None` keeps the audit-only listener usable in focused tests.
    #[cfg(feature = "cluster")]
    pub membership: Option<Arc<crate::cluster::membership::MembershipController>>,
    pub audit_routes_enabled: bool,
}

/// Bind `127.0.0.1:0`, return the OS-assigned address + the accept-loop handle.
/// Mirrors [`crate::daemon::healthz::bind_and_serve`].
pub async fn bind_and_serve(state: AuditRpcState) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind audit-RPC listener on {addr}"))?;
    let local = listener.local_addr()?;
    let task = tokio::spawn(async move { run_accept_loop(listener, state).await });
    Ok((local, task))
}

async fn run_accept_loop(listener: TcpListener, state: AuditRpcState) -> Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "audit-RPC connection task failed");
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                // Drop the connection immediately if we're at the concurrency
                // cap — never queue (queuing is what a slowloris flood wants).
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    tracing::warn!("audit-RPC at connection cap; dropping connection");
                    continue;
                };
                let state = state.clone();
                connections.spawn(async move {
                    let _permit = permit; // released when this task ends
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                        handle_one(stream, peer, &state),
                    )
                    .await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "audit-RPC accept failed");
            }
        }
    }
}

/// Parsed request: method, path, bearer token, body bytes.
struct Parsed {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
}

/// Read + parse a single HTTP request (request line + headers + Content-Length
/// body), capped. Returns `None` on a malformed/oversized request.
async fn read_request(stream: &mut TcpStream) -> Option<Parsed> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut header_end: Option<usize> = None;
    // Read until headers complete or cap hit.
    while buf.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let end = pos + 4;
            if end > MAX_REQUEST_BYTES {
                return None;
            }
            header_end = Some(end);
            break;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return None;
        }
    }
    let header_end = header_end?;
    let head = std::str::from_utf8(&buf[..header_end - 4]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut rl = request_line.split_whitespace();
    let method = rl.next()?.to_string();
    let path = rl.next()?.to_string();
    if rl.next()? != "HTTP/1.1" || rl.next().is_some() {
        return None;
    }

    let mut bearer = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("authorization") {
            if bearer.is_some() {
                return None;
            }
            let val = value.trim();
            bearer = extract_bearer_token(val).map(|t| t.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return None;
            }
            content_length = Some(value.trim().parse::<usize>().ok()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    let content_length = content_length?;
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    // Body bytes already buffered after the header terminator.
    let mut body: Vec<u8> = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > content_length {
            return None;
        }
    }
    if body.len() != content_length {
        return None;
    }
    Some(Parsed {
        method,
        path,
        bearer,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn handle_one(mut stream: TcpStream, peer: SocketAddr, state: &AuditRpcState) -> Result<()> {
    // Layer 1 — loopback peer guard (defense-in-depth vs a future bind regression).
    if !peer.ip().is_loopback() {
        let _ = stream
            .write_all(http_response(403, "non-loopback peer rejected").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let source = peer.ip().to_string();

    let Some(req) = read_request(&mut stream).await else {
        let _ = stream
            .write_all(http_response(400, "malformed or oversized request").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    };

    // Only POST to a known endpoint (/audit or one of the approval-token verbs).
    let req_path = req.path.split('?').next().unwrap_or("").to_string();
    #[cfg(feature = "cluster")]
    let membership_route = matches!(
        req_path.as_str(),
        "/membership/list"
            | "/membership/status"
            | "/membership/runtime-health"
            | "/membership/revoke"
            | "/membership/revoke/status"
            | "/membership/invite"
            | "/membership/confirm"
            | "/membership/legacy-pending"
    );
    #[cfg(not(feature = "cluster"))]
    let membership_route = false;
    let audit_route = matches!(
        req_path.as_str(),
        "/audit"
            | "/fullauto-token/mint"
            | "/fullauto-token/consume"
            | "/jobs-run-token/mint"
            | "/jobs-run-token/consume"
    );
    if req.method != "POST" || (!membership_route && !(state.audit_routes_enabled && audit_route)) {
        let _ = stream
            .write_all(http_response(404, "not found").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Layer 2 — bearer auth (cooldown → constant-time compare). Auth failures
    // are NOT WAL-recorded (avoids a forged-frame paradox + WAL spam).
    let now = std::time::Instant::now();
    if state.cooldown.is_locked(&source, now) {
        let _ = stream
            .write_all(http_response(429, "auth cooldown active").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let ok = req
        .bearer
        .as_deref()
        .is_some_and(|t| constant_time_token_eq(t, &state.token));
    if !ok {
        state.cooldown.record_failure(&source, now);
        let _ = stream
            .write_all(http_response(401, "unauthorized").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    state.cooldown.record_success(&source);

    if req_path == "/health" {
        let _ = stream
            .write_all(http_response_json(200, "{\"ok\":true}").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    #[cfg(feature = "cluster")]
    if req_path.starts_with("/membership/") {
        let Some(controller) = state.membership.as_ref().cloned() else {
            let _ = stream
                .write_all(http_response(503, "membership authority unavailable").as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(());
        };
        let membership_path = req_path.clone();
        let membership_body = req.body;
        let result = tokio::task::spawn_blocking(move || {
            process_membership_request(&controller, &membership_path, &membership_body)
        })
        .await
        .map_err(|error| anyhow::anyhow!("membership worker failed: {error}"))
        .and_then(|result| result);
        let (status, body) = match result {
            Ok(value) => (200, serde_json::to_string(&value)?),
            Err(error) => (
                422,
                serde_json::json!({ "error": format!("{error:#}") }).to_string(),
            ),
        };
        let _ = stream
            .write_all(http_response_json(status, &body).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // GR-RESID-D34 — FULL-AUTO single-use token endpoints (auth already passed).
    if req_path == "/fullauto-token/mint" {
        let resp = match state
            .fullauto
            .mint(super::fullauto_token::FULLAUTO_TOKEN_TTL)
        {
            Some(tok) => http_response_json(200, &format!("{{\"token\":{tok:?}}}")),
            None => http_response(500, "token mint failed (RNG unavailable)"),
        };
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    if req_path == "/fullauto-token/consume" {
        let candidate = serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(str::to_string));
        let ok = candidate
            .as_deref()
            .is_some_and(|t| state.fullauto.consume(t, std::time::Instant::now()));
        let status = if ok { 200 } else { 401 };
        let _ = stream
            .write_all(http_response_json(status, &format!("{{\"ok\":{ok}}}")).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    if req_path == "/jobs-run-token/mint" {
        let binding = serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|value| {
                value
                    .get("request_binding_sha256")
                    .and_then(|field| field.as_str())
                    .map(str::to_string)
            });
        let token = binding.as_deref().and_then(|binding| {
            state
                .fullauto
                .mint_jobs_run(binding, super::fullauto_token::JOBS_RUN_TOKEN_TTL)
        });
        let (status, body) = match token.zip(binding) {
            Some((token, binding)) => {
                // A GUI approval token is an authority-bearing capability, not
                // a convenience nonce. Persist its exact request binding before
                // releasing the token to the caller. If the append fails, burn
                // the still-secret token and fail closed.
                let payload = serde_json::to_vec(&serde_json::json!({
                    "action": "ExecArbitrary",
                    "decision": "operator_approval_token_minted",
                    "confirmation_source": "gui_dialog",
                    "authority_boundary": "same_uid_operator",
                    "request_binding_sha256": &binding,
                    "ts_ns": crate::time::now_unix_ns(),
                }))
                .expect("jobs-run approval audit contains only infallible JSON values");
                let header =
                    crate::wal::HeaderBuilder::new(EVENT_TYPE_PERMISSION_GRANTED, &payload)
                        .flags(crate::wal::EventFlags::SYNTHETIC)
                        .build();
                match state.writer.append(header, payload).await {
                    Ok(_) => (200, format!("{{\"token\":{token:?}}}")),
                    Err(error) => {
                        let _ = state.fullauto.consume_jobs_run(
                            &token,
                            &binding,
                            std::time::Instant::now(),
                        );
                        tracing::error!(%error, "jobs-run approval audit failed; token revoked");
                        (
                            500,
                            "{\"error\":\"mandatory approval audit append failed\"}".into(),
                        )
                    }
                }
            }
            None => (
                400,
                "{\"error\":\"invalid binding or token mint failed\"}".into(),
            ),
        };
        let _ = stream
            .write_all(http_response_json(status, &body).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    if req_path == "/jobs-run-token/consume" {
        let parsed = serde_json::from_slice::<serde_json::Value>(&req.body).ok();
        let token = parsed
            .as_ref()
            .and_then(|value| value.get("token"))
            .and_then(|field| field.as_str());
        let binding = parsed
            .as_ref()
            .and_then(|value| value.get("request_binding_sha256"))
            .and_then(|field| field.as_str());
        let ok = token.zip(binding).is_some_and(|(token, binding)| {
            state
                .fullauto
                .consume_jobs_run(token, binding, std::time::Instant::now())
        });
        let status = if ok { 200 } else { 401 };
        let _ = stream
            .write_all(http_response_json(status, &format!("{{\"ok\":{ok}}}")).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Body: {"event_type": u8, "event_subtype"?: u8,
    //        "payload_b64": "<base64-standard>"}. Missing subtype is zero for
    // backward compatibility with pre-subtype clients.
    let parsed: Result<(u8, u8, Vec<u8>), &str> = (|| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).map_err(|_| "bad json")?;
        let event_type = v
            .get("event_type")
            .and_then(|e| e.as_u64())
            .and_then(|e| u8::try_from(e).ok())
            .ok_or("missing event_type")?;
        let event_subtype = match v.get("event_subtype") {
            None => 0,
            Some(value) => value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or("invalid event_subtype")?,
        };
        let payload_b64 = v
            .get("payload_b64")
            .and_then(|p| p.as_str())
            .ok_or("missing payload_b64")?;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|_| "bad payload base64")?;
        Ok((event_type, event_subtype, payload))
    })();

    let (event_type, event_subtype, payload) = match parsed {
        Ok(x) => x,
        Err(reason) => {
            emit_reject(state, reason).await;
            let _ = stream
                .write_all(http_response(400, reason).as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // Layer 3 — compile-time event-type allowlist (anti-poisoning gate).
    if !is_allowed_client_event_pair(event_type, event_subtype) {
        let reason = if event_subtype == 0 && event_type != EVENT_TYPE_EXTENDED {
            // Preserve the historical rejection contract for old top-level
            // clients; subtype-aware identity failures use the new reason.
            "event_type_not_allowed"
        } else {
            "event_identity_not_allowed"
        };
        emit_reject(state, reason).await;
        let _ = stream
            .write_all(http_response(422, reason).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Forward the frame into the daemon's single writer.
    let header = crate::wal::HeaderBuilder::new(event_type, &payload)
        .event_subtype(event_subtype)
        .build();
    match state.writer.append(header, payload).await {
        Ok(offset) => {
            emit_accept(state, event_type, event_subtype).await;
            let body = format!("{{\"ok\":true,\"offset\":{offset}}}");
            let _ = stream
                .write_all(http_response_json(200, &body).as_bytes())
                .await;
        }
        Err(e) => {
            let _ = stream
                .write_all(http_response(500, &format!("append failed: {e}")).as_bytes())
                .await;
        }
    }
    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(feature = "cluster")]
fn process_membership_request(
    controller: &crate::cluster::membership::MembershipController,
    path: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    match path {
        "/membership/list" => Ok(serde_json::to_value(controller.snapshot()?)?),
        "/membership/status" => Ok(serde_json::to_value(
            controller.snapshot()?.into_envelope()?,
        )?),
        "/membership/runtime-health" => Ok(serde_json::to_value(controller.runtime_health()?)?),
        "/membership/revoke" => {
            let request: crate::cluster::membership::MembershipRevokeRequest =
                serde_json::from_slice(body).context("invalid membership revoke body")?;
            request.binding.validate()?;
            Ok(serde_json::to_value(controller.revoke_bound(
                &request.binding,
                crate::time::now_unix_i64(),
            )?)?)
        }
        "/membership/revoke/status" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct RevocationStatusRequest {
                request_id: String,
            }
            let request: RevocationStatusRequest =
                serde_json::from_slice(body).context("invalid membership revoke status body")?;
            crate::cluster::membership::validate_revocation_request_id(&request.request_id)?;
            Ok(serde_json::to_value(
                controller.revocation_status(&request.request_id)?,
            )?)
        }
        "/membership/invite" => {
            let request: crate::cluster::membership::MembershipInviteRequest =
                serde_json::from_slice(body).context("invalid membership invite body")?;
            let key: [u8; 32] = hex::decode(&request.signing_public_key_hex)
                .context("invite signing key is not hexadecimal")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invite signing key must be 32 bytes"))?;
            let now_unix = crate::time::now_unix_i64();
            Ok(serde_json::to_value(controller.create_invite(
                &request.stable_node_id,
                &key,
                request.carrier,
                &request.transport_identity,
                &request.endpoint,
                &request.label,
                now_unix,
                request.expires_at_unix.min(now_unix.saturating_add(300)),
            )?)?)
        }
        "/membership/confirm" => {
            let request: crate::cluster::membership::MembershipConfirmRequest =
                serde_json::from_slice(body).context("invalid membership confirm body")?;
            Ok(serde_json::to_value(controller.confirm_invite(
                &request.invite_id,
                &request.attestation,
                request.carrier,
                &request.authenticated_transport,
                &request.endpoint,
                crate::time::now_unix_i64(),
            )?)?)
        }
        "/membership/legacy-pending" => {
            let request: crate::cluster::membership::MembershipLegacyPendingRequest =
                serde_json::from_slice(body).context("invalid legacy membership body")?;
            Ok(serde_json::to_value(controller.record_legacy_pending(
                request.carrier,
                &request.transport_identity,
                &request.endpoint,
                &request.label,
                crate::time::now_unix_i64(),
            )?)?)
        }
        _ => unreachable!("membership route allowlisted"),
    }
}

async fn emit_accept(state: &AuditRpcState, forwarded_event_type: u8, forwarded_event_subtype: u8) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "forwarded_event_type": forwarded_event_type,
        "forwarded_event_subtype": forwarded_event_subtype,
    }))
    .expect("audit-RPC accept payload contains only infallible JSON values");
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_AUDIT_RPC_ACCEPT, &payload).build();
    if let Err(error) = state.writer.append(header, payload).await {
        tracing::warn!(%error, "audit-RPC accept marker append failed");
    }
}

async fn emit_reject(state: &AuditRpcState, reason: &str) {
    let payload = serde_json::to_vec(&serde_json::json!({ "reason": reason }))
        .expect("audit-RPC reject payload contains only infallible JSON values");
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_AUDIT_RPC_REJECT, &payload).build();
    if let Err(error) = state.writer.append(header, payload).await {
        tracing::warn!(%error, "audit-RPC reject marker append failed");
    }
}

fn http_response(status: u16, msg: &str) -> String {
    http_response_json(status, &format!("{{\"error\":{msg:?}}}"))
}

fn http_response_json(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}
