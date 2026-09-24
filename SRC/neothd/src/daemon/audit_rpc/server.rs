//! AUDIT-RPC-01 — the daemon-side same-user IPC listener.
//!
//! Binds an OS-authenticated local endpoint, accepts same-user one-shot CLIs,
//! and (after the transport peer proof + bearer auth + compile-time event-type allowlist)
//! appends the forwarded frame into the daemon's single WAL writer, recording a
//! `0xAE AUDIT_RPC_ACCEPT` / `0xAF AUDIT_RPC_REJECT` marker. See the module-level
//! doc in `mod.rs` for the full security model.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::daemon::gui_chat_protocol as gui;
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
    0x8E, // PTY_SESSION_STARTED    — `neoth terminal` opened a PTY session
    0x8F, // PTY_SESSION_ENDED      — `neoth terminal` closed a PTY session
    0x9B, // IDENTITY_MERGED        — `neoth identity merge` folded two identities
    0xBB, // OPERATOR_FEEDBACK      — chat detected an operator correction
    // GOLD-LF-P1-05 — `neoth mcp call` must preserve the MCP adapter's
    // compatibility outcome on the daemon-owned writer alongside its typed
    // TrustDecision. These two payloads contain only server/tool metadata.
    0xC0, // MCP_TOOL_CALLED
    0xC1, // MCP_TOOL_REJECTED
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
    0xDE, // SELF_UPDATE_REJECTED   — staged update failed integrity validation
    0x54, // RISK_CONFIRM_GRANTED   — `neoth risk-confirm` granted a risk-override lease
    0xF5, // MEMORY_TRANSFER_EXPORTED — `neoth transfer export` sealed a bundle
    0xF6, // RECON_RUN              — `neoth recon uncover/tlsx` ran a gated recon tool
    0xFE, // LOYAL_BUDDY_ACTIVATED — `neoth profile mode apply loyal-buddy`
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
    ExtendedSubtype::SkillRemovalIntent as u8,
    ExtendedSubtype::SkillRemovalResult as u8,
    ExtendedSubtype::SkillAuthorityDecision as u8,
    // GOLD-LF-P1-01. Only the two OS-effect pairs are listed: `os_tools::gate`
    // is the one caller that reaches the WAL over this RPC route (via
    // `AuditSink::DaemonRpc`). Channel egress and media calls hold an
    // in-process `WalWriterHandle`, so admitting their subtypes here would
    // widen the client-accepted surface without a caller that needs it.
    ExtendedSubtype::OsFileWriteIntent as u8,
    ExtendedSubtype::OsFileWriteResult as u8,
    ExtendedSubtype::OsAppLaunchIntent as u8,
    ExtendedSubtype::OsAppLaunchResult as u8,
    // GOLD-LF-P1-05 — one-shot commands may route their final canonical Gate
    // decision through the daemon-owned WAL writer.
    ExtendedSubtype::TrustDecision as u8,
    // A direct generated-codegraph result receipt is observational context
    // evidence, never an execution authority or delivery acknowledgement.
    ExtendedSubtype::CodeMapRecallResolved as u8,
];

/// Max inbound request size (headers + body). Audit payloads are small.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Max body size accepted (tighter than the request cap).
const MAX_BODY_BYTES: usize = super::DAEMON_PLAIN_CHAT_TRANSPORT_BODY_MAX_BYTES;
/// Per-connection wall-clock budget. A client that opens a connection and then
/// stalls (slowloris) is dropped after this — bounds resource pinning.
const CONNECTION_TIMEOUT_SECS: u64 = 5;
/// Cap on concurrent in-flight connections. A local process can't exhaust the
/// daemon's FD table / task pool by holding connections open — excess
/// connections are dropped immediately (the one-shot falls back to its
/// un-audited path, fail-open on availability).
const MAX_CONCURRENT_CONNS: usize = 32;
pub(super) const MAX_SKILL_AUDIT_INFLIGHT: usize = 32;
const MAX_SKILL_AUDIT_COMPLETED: usize = 65_536;
static SKILL_AUDIT_COORDINATOR: OnceLock<Arc<SkillAuditCoordinator>> = OnceLock::new();

#[derive(Default)]
pub(super) struct SkillAuditCoordinator {
    state: tokio::sync::Mutex<SkillAuditCoordinatorState>,
}

#[derive(Default)]
struct SkillAuditCoordinatorState {
    entries: BTreeMap<String, SkillAuditEntry>,
    completed_order: VecDeque<String>,
    inflight: usize,
}

enum SkillAuditEntry {
    InFlight {
        payload_sha256: String,
        receiver: tokio::sync::watch::Receiver<SkillAuditWorkerResult>,
    },
    Completed {
        payload_sha256: String,
        offset: u64,
    },
}

#[derive(Clone)]
enum SkillAuditWorkerResult {
    Pending,
    Appended(u64),
    Failed(Arc<str>),
}

enum SkillAuditAdmission {
    Wait(tokio::sync::watch::Receiver<SkillAuditWorkerResult>),
    Complete(SkillAuditAppendOutcome),
    Start {
        sender: tokio::sync::watch::Sender<SkillAuditWorkerResult>,
        receiver: tokio::sync::watch::Receiver<SkillAuditWorkerResult>,
    },
}

fn skill_audit_coordinator() -> Arc<SkillAuditCoordinator> {
    Arc::clone(SKILL_AUDIT_COORDINATOR.get_or_init(|| Arc::new(SkillAuditCoordinator::default())))
}

fn skill_audit_dedup_binding(
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> Result<Option<(String, String)>> {
    if event_type != EVENT_TYPE_EXTENDED
        || !matches!(
            ExtendedSubtype::from_u8(event_subtype),
            Some(
                ExtendedSubtype::SkillInstallIntent
                    | ExtendedSubtype::SkillInstallResult
                    | ExtendedSubtype::SkillRemovalIntent
                    | ExtendedSubtype::SkillRemovalResult
                    | ExtendedSubtype::SkillAuthorityDecision
            )
        )
    {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_slice(payload).context("invalid Skill mutation audit payload")?;
    let audit_event_id = value
        .get("audit_event_id")
        .and_then(serde_json::Value::as_str)
        .context("Skill mutation audit payload is missing audit_event_id")?;
    if audit_event_id.len() != 64
        || !audit_event_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("Skill mutation audit_event_id must be 64 lowercase hex characters");
    }
    let operation_id = value
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .context("Skill mutation audit payload is missing operation_id")?;
    if operation_id.len() != 32
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("Skill mutation operation_id must be 32 lowercase hex characters");
    }
    let key = format!("{event_subtype:02x}:{audit_event_id}");
    let payload_sha256 = hex::encode(Sha256::digest(payload));
    Ok(Some((key, payload_sha256)))
}

fn validate_code_map_result_prepared_payload(
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> Result<()> {
    if event_type != EVENT_TYPE_EXTENDED
        || event_subtype != ExtendedSubtype::CodeMapRecallResolved as u8
    {
        return Ok(());
    }
    let value: serde_json::Value =
        serde_json::from_slice(payload).context("invalid code-map result receipt payload")?;
    let object = value
        .as_object()
        .context("code-map result receipt must be an object")?;
    const KEYS: &[&str] = &[
        "schema",
        "status",
        "surface",
        "request_sha256",
        "tool",
        "root_identity_hash_sha256",
        "index_generation",
        "graph_generation",
        "child_public_result_sha256",
        "child_public_result_bytes",
        "final_public_result_sha256",
        "final_public_result_bytes",
        "ts_unix",
    ];
    anyhow::ensure!(
        object.len() == KEYS.len() && KEYS.iter().all(|key| object.contains_key(*key)),
        "unexpected code-map result receipt fields"
    );
    let string = |key: &str| object.get(key).and_then(serde_json::Value::as_str);
    let hash = |key: &str| -> Result<()> {
        let value = string(key).with_context(|| format!("missing {key}"))?;
        anyhow::ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{key} must be a lowercase SHA-256 hex digest"
        );
        Ok(())
    };
    anyhow::ensure!(
        string("schema") == Some("neoth.code_map.recall.audit.v1"),
        "invalid code-map result receipt schema"
    );
    anyhow::ensure!(
        string("status") == Some("final_tool_result_prepared"),
        "invalid code-map result receipt status"
    );
    anyhow::ensure!(
        string("surface") == Some("direct_cli_mcp"),
        "invalid code-map result receipt surface"
    );
    anyhow::ensure!(
        matches!(
            string("tool"),
            Some(
                "codegraph_recall_v1"
                    | "codegraph_relevant_files"
                    | "codegraph_callers"
                    | "codegraph_callees"
            )
        ),
        "invalid code-map result receipt tool"
    );
    for key in [
        "request_sha256",
        "root_identity_hash_sha256",
        "child_public_result_sha256",
        "final_public_result_sha256",
    ] {
        hash(key)?;
    }
    let index = object
        .get("index_generation")
        .and_then(serde_json::Value::as_i64)
        .context("missing index generation")?;
    let graph = object
        .get("graph_generation")
        .and_then(serde_json::Value::as_i64)
        .context("missing graph generation")?;
    anyhow::ensure!(
        index > 0 && index == graph,
        "invalid code-map result receipt generations"
    );
    for key in ["child_public_result_bytes", "final_public_result_bytes"] {
        anyhow::ensure!(
            object
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|bytes| bytes <= crate::mcp::transport::MAX_MCP_FRAME_BYTES as u64),
            "invalid {key}"
        );
    }
    anyhow::ensure!(
        object
            .get("ts_unix")
            .and_then(serde_json::Value::as_i64)
            .is_some(),
        "missing ts_unix"
    );
    Ok(())
}

async fn authenticate_skill_authority_ingress(
    home: &Path,
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> Result<()> {
    if event_type != EVENT_TYPE_EXTENDED
        || event_subtype != ExtendedSubtype::SkillAuthorityDecision as u8
    {
        return Ok(());
    }
    let home = home.to_path_buf();
    let payload = payload.to_vec();
    tokio::task::spawn_blocking(move || {
        crate::skills::authority::authenticate_authority_wal_ingress(&home, &payload)
    })
    .await
    .context("join Skill authority audit-RPC authentication")??;
    Ok(())
}

fn notify_runtime_authority_transition_after_ack(home: &Path, event_type: u8, event_subtype: u8) {
    use crate::skills::registry::RuntimeAuthorityTransitionKind;

    if event_type != EVENT_TYPE_EXTENDED {
        return;
    }
    let kind = match ExtendedSubtype::from_u8(event_subtype) {
        Some(ExtendedSubtype::SkillInstallIntent) => RuntimeAuthorityTransitionKind::InstallIntent,
        Some(ExtendedSubtype::SkillInstallResult) => RuntimeAuthorityTransitionKind::InstallResult,
        Some(ExtendedSubtype::SkillRemovalIntent) => RuntimeAuthorityTransitionKind::RemovalIntent,
        Some(ExtendedSubtype::SkillRemovalResult) => RuntimeAuthorityTransitionKind::RemovalResult,
        Some(ExtendedSubtype::SkillAuthorityDecision) => {
            RuntimeAuthorityTransitionKind::AuthorityDecision
        }
        _ => return,
    };
    crate::skills::registry::notify_runtime_authority_transition(home, kind);
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SkillAuditAppendOutcome {
    Appended(u64),
    Duplicate,
    Conflict,
    CapacityReached,
}

impl SkillAuditCoordinator {
    #[cfg(test)]
    pub(super) async fn inflight_count(&self) -> usize {
        self.state.lock().await.inflight
    }

    async fn finish(&self, dedup_key: &str, payload_sha256: &str, result: &Result<u64>) {
        let mut state = self.state.lock().await;
        let matches_worker = matches!(
            state.entries.get(dedup_key),
            Some(SkillAuditEntry::InFlight {
                payload_sha256: existing,
                ..
            }) if existing == payload_sha256
        );
        if !matches_worker {
            return;
        }
        state.inflight = state.inflight.saturating_sub(1);
        match result {
            Ok(offset) => {
                state.entries.insert(
                    dedup_key.to_string(),
                    SkillAuditEntry::Completed {
                        payload_sha256: payload_sha256.to_string(),
                        offset: *offset,
                    },
                );
                state.completed_order.push_back(dedup_key.to_string());
                while state.completed_order.len() > MAX_SKILL_AUDIT_COMPLETED {
                    let Some(expired) = state.completed_order.pop_front() else {
                        break;
                    };
                    if matches!(
                        state.entries.get(&expired),
                        Some(SkillAuditEntry::Completed { .. })
                    ) {
                        state.entries.remove(&expired);
                    }
                }
            }
            Err(_) => {
                state.entries.remove(dedup_key);
            }
        }
    }
}

async fn await_skill_audit_worker(
    mut receiver: tokio::sync::watch::Receiver<SkillAuditWorkerResult>,
    joined_existing: bool,
) -> Result<SkillAuditAppendOutcome> {
    loop {
        let result = receiver.borrow().clone();
        match result {
            SkillAuditWorkerResult::Pending => {
                receiver
                    .changed()
                    .await
                    .context("idempotent Skill audit worker ended without a result")?;
            }
            SkillAuditWorkerResult::Appended(offset) => {
                return Ok(if joined_existing {
                    SkillAuditAppendOutcome::Duplicate
                } else {
                    SkillAuditAppendOutcome::Appended(offset)
                });
            }
            SkillAuditWorkerResult::Failed(error) => {
                anyhow::bail!("append idempotent Skill mutation audit: {error}");
            }
        }
    }
}

/// Join or start one bounded idempotent Skill-audit append. Connection
/// cancellation drops only its watch receiver; the sole per-key worker remains
/// bounded by `MAX_SKILL_AUDIT_INFLIGHT` and completes the durable append.
pub(super) async fn append_skill_audit_idempotently_with_coordinator(
    coordinator: Arc<SkillAuditCoordinator>,
    writer: WalWriterHandle,
    event_type: u8,
    event_subtype: u8,
    payload: Vec<u8>,
    dedup_key: String,
    payload_sha256: String,
) -> Result<SkillAuditAppendOutcome> {
    let admission = {
        let mut state = coordinator.state.lock().await;
        if let Some(entry) = state.entries.get(&dedup_key) {
            match entry {
                SkillAuditEntry::InFlight {
                    payload_sha256: existing,
                    receiver,
                } if existing == &payload_sha256 => SkillAuditAdmission::Wait(receiver.clone()),
                SkillAuditEntry::Completed {
                    payload_sha256: existing,
                    offset,
                } if existing == &payload_sha256 => {
                    let _ = offset;
                    SkillAuditAdmission::Complete(SkillAuditAppendOutcome::Duplicate)
                }
                _ => SkillAuditAdmission::Complete(SkillAuditAppendOutcome::Conflict),
            }
        } else if state.inflight >= MAX_SKILL_AUDIT_INFLIGHT {
            SkillAuditAdmission::Complete(SkillAuditAppendOutcome::CapacityReached)
        } else {
            let (sender, receiver) = tokio::sync::watch::channel(SkillAuditWorkerResult::Pending);
            state.entries.insert(
                dedup_key.clone(),
                SkillAuditEntry::InFlight {
                    payload_sha256: payload_sha256.clone(),
                    receiver: receiver.clone(),
                },
            );
            state.inflight += 1;
            SkillAuditAdmission::Start { sender, receiver }
        }
    };
    match admission {
        SkillAuditAdmission::Complete(outcome) => Ok(outcome),
        SkillAuditAdmission::Wait(receiver) => await_skill_audit_worker(receiver, true).await,
        SkillAuditAdmission::Start { sender, receiver } => {
            let worker_coordinator = Arc::clone(&coordinator);
            let worker_key = dedup_key;
            let worker_sha256 = payload_sha256;
            tokio::spawn(async move {
                let header = crate::wal::HeaderBuilder::new(event_type, &payload)
                    .event_subtype(event_subtype)
                    .build();
                let result = writer
                    .append(header, payload)
                    .await
                    .context("append idempotent Skill mutation audit");
                worker_coordinator
                    .finish(&worker_key, &worker_sha256, &result)
                    .await;
                let notification = match result {
                    Ok(offset) => SkillAuditWorkerResult::Appended(offset),
                    Err(error) => SkillAuditWorkerResult::Failed(Arc::from(format!("{error:#}"))),
                };
                sender.send_replace(notification);
            });
            await_skill_audit_worker(receiver, false).await
        }
    }
}

pub(super) async fn append_skill_audit_idempotently(
    writer: WalWriterHandle,
    event_type: u8,
    event_subtype: u8,
    payload: Vec<u8>,
    dedup_key: String,
    payload_sha256: String,
) -> Result<SkillAuditAppendOutcome> {
    append_skill_audit_idempotently_with_coordinator(
        skill_audit_coordinator(),
        writer,
        event_type,
        event_subtype,
        payload,
        dedup_key,
        payload_sha256,
    )
    .await
}

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

#[cfg(test)]
mod w61_code_map_result_receipt_tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "neoth.code_map.recall.audit.v1",
            "status": "final_tool_result_prepared",
            "surface": "direct_cli_mcp",
            "request_sha256": "a".repeat(64),
            "tool": "codegraph_callers",
            "root_identity_hash_sha256": "b".repeat(64),
            "index_generation": 7,
            "graph_generation": 7,
            "child_public_result_sha256": "c".repeat(64),
            "child_public_result_bytes": 12,
            "final_public_result_sha256": "d".repeat(64),
            "final_public_result_bytes": 12,
            "ts_unix": 1,
        }))
        .unwrap()
    }

    #[test]
    fn code_map_result_receipt_is_the_one_observational_client_subtype() {
        let subtype = ExtendedSubtype::CodeMapRecallResolved as u8;
        assert!(ALLOWED_CLIENT_EXTENDED_SUBTYPES.contains(&subtype));
        assert!(is_allowed_client_event_pair(EVENT_TYPE_EXTENDED, subtype));
        assert!(
            validate_code_map_result_prepared_payload(EVENT_TYPE_EXTENDED, subtype, &payload(),)
                .is_ok()
        );
    }

    #[test]
    fn code_map_result_receipt_rejects_raw_or_mismatched_generation_claims() {
        let subtype = ExtendedSubtype::CodeMapRecallResolved as u8;
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["root"] = serde_json::json!("C:/private");
        assert!(
            validate_code_map_result_prepared_payload(
                EVENT_TYPE_EXTENDED,
                subtype,
                &serde_json::to_vec(&value).unwrap(),
            )
            .is_err()
        );
        value.as_object_mut().unwrap().remove("root");
        value["graph_generation"] = serde_json::json!(8);
        assert!(
            validate_code_map_result_prepared_payload(
                EVENT_TYPE_EXTENDED,
                subtype,
                &serde_json::to_vec(&value).unwrap(),
            )
            .is_err()
        );
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
    #[cfg(feature = "cluster")]
    pub outbound_task_delegate:
        Option<Arc<crate::cluster::runtime_supervisor::OutboundTaskDelegateController>>,
    pub audit_routes_enabled: bool,
    /// W39 is installed by `run_serve` after the daemon has constructed its
    /// owned runtime. `None` keeps focused audit-only listeners fail-closed for
    /// chat instead of constructing a provider or a second listener here.
    pub(crate) chat_runtime: Option<Arc<crate::daemon::chat_runtime::DaemonChatRuntime>>,
    /// W41 v1 route runtime. It owns staged attachment/ticket/grant state and
    /// shares the existing daemon provider admission; this listener owns no provider.
    pub(crate) gui_chat_runtime: Option<Arc<dyn gui::GuiChatRuntime>>,
    /// W682 browser authority; minted only over the same-user audit-RPC route.
    pub(crate) webchat: Option<Arc<crate::daemon::webchat::WebChatState>>,
}

/// Bind the OS-authenticated same-user endpoint for one daemon incarnation.
/// No TCP fallback exists: unsupported or unverifiable local transports fail
/// daemon startup closed.
pub(crate) async fn bind_and_serve(
    home: &Path,
    endpoint_nonce: &str,
    state: AuditRpcState,
) -> Result<(super::transport::AuditEndpointV2, JoinHandle<Result<()>>)> {
    let (listener, endpoint) = super::transport::bind(home, endpoint_nonce)
        .await
        .context("bind same-user audit-RPC transport")?;
    let home = home.to_path_buf();
    let task = tokio::spawn(async move { run_accept_loop(listener, state, home).await });
    Ok((endpoint, task))
}

async fn run_accept_loop(
    mut listener: super::transport::AuditListener,
    state: AuditRpcState,
    home: std::path::PathBuf,
) -> Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));
    // Held `/chat/v1/attach` streams are not ordinary request work. They get a
    // separate bounded admission budget and never consume a W39/v1 provider
    // admission; the GUI runtime still shares the provider permit at start.
    let attach_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));
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
            Ok(stream) => {
                // `AuditListener::accept` returns only after the OS attests the
                // peer as the daemon's own user. Apply the application
                // concurrency cap after that identity proof and never queue.
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    tracing::warn!("audit-RPC at connection cap; dropping connection");
                    continue;
                };
                let state = state.clone();
                let home = home.clone();
                let attach_sem = Arc::clone(&attach_sem);
                connections.spawn(async move {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                        handle_one_pre_admission(stream, &state, &home),
                    )
                    .await
                    {
                        Ok(Ok(ConnectionOutcome::Complete)) => {}
                        Ok(Ok(ConnectionOutcome::GuiChatAttachAdmitted {
                            mut stream,
                            request,
                        })) => {
                            drop(permit);
                            let Ok(_attach_permit) = attach_sem.try_acquire_owned() else {
                                let _ = stream
                                    .write_all(
                                        http_response(503, "gui chat attach capacity reached")
                                            .as_bytes(),
                                    )
                                    .await;
                                let _ = stream.shutdown().await;
                                return;
                            };
                            let Some(runtime) = state.gui_chat_runtime.as_ref().cloned() else {
                                let _ = stream
                                    .write_all(
                                        http_response(503, "gui chat runtime unavailable")
                                            .as_bytes(),
                                    )
                                    .await;
                                let _ = stream.shutdown().await;
                                return;
                            };
                            if let Err(error) = runtime.attach(stream, request).await {
                                tracing::warn!(?error, "audit-RPC GUI attach failed");
                            }
                        }
                        Ok(Ok(ConnectionOutcome::ChatAdmitted {
                            mut stream,
                            request,
                        })) => {
                            let _permit = permit;
                            let Some(runtime) = state.chat_runtime.as_ref().cloned() else {
                                let _ = stream
                                    .write_all(
                                        http_response(503, "chat runtime unavailable").as_bytes(),
                                    )
                                    .await;
                                let _ = stream.shutdown().await;
                                return;
                            };
                            if let Err(error) =
                                runtime.handle_authenticated_turn(stream, request).await
                            {
                                tracing::warn!(%error, "audit-RPC daemon chat operation failed");
                            }
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "audit-RPC connection failed");
                        }
                        Err(_) => {
                            tracing::warn!("audit-RPC connection timed out");
                        }
                    }
                });
            }
            Err(error) => {
                return Err(error).context(
                    "audit-RPC same-user listener failed; authority boundary is no longer live",
                );
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

/// A five-second connection either completed an ordinary existing route or
/// admitted exactly one sealed chat request. Only the latter escapes the
/// slow-client deadline, carrying the already peer- and bearer-authenticated
/// stream directly to the daemon runtime.
enum ConnectionOutcome {
    Complete,
    GuiChatAttachAdmitted {
        stream: super::transport::AuditStream,
        request: gui::GuiChatAttachRequest,
    },
    ChatAdmitted {
        stream: super::transport::AuditStream,
        request: super::DaemonPlainChatRequest,
    },
}

/// Read + parse a single HTTP request (request line + headers + Content-Length
/// body), capped. Returns `None` on a malformed/oversized request.
async fn read_request(stream: &mut super::transport::AuditStream) -> Option<Parsed> {
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

async fn handle_one_pre_admission(
    mut stream: super::transport::AuditStream,
    state: &AuditRpcState,
    home: &Path,
) -> Result<ConnectionOutcome> {
    // Layer 1 is enforced by `AuditListener::accept`: the peer's kernel token
    // (UID/SID) must exactly match the daemon user before this function runs.
    let source = "same-user-ipc";

    let Some(req) = read_request(&mut stream).await else {
        let _ = stream
            .write_all(http_response(400, "malformed or oversized request").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    };

    // Only POST to a known endpoint (/audit or one of the approval-token verbs).
    let req_path = req.path.split('?').next().unwrap_or("").to_string();
    // Chat accepts no query component so the exact sealed path cannot become a
    // carrier for later parser controls.
    let chat_route = req.path == "/chat/turn";
    let gui_chat_route = matches!(
        req.path.as_str(),
        gui::GUI_CHAT_V1_CONSENT_PREFLIGHT_PATH
            | gui::GUI_CHAT_V1_CONSENT_DECIDE_PATH
            | gui::GUI_CHAT_V1_START_PATH
            | gui::GUI_CHAT_V1_ATTACH_EXCHANGE_PATH
            | gui::GUI_CHAT_V1_ATTACH_PATH
            | gui::GUI_CHAT_V1_CANCEL_PATH
            | gui::GUI_CHAT_V1_STATUS_PATH
            | gui::GUI_CHAT_V1_ACTIVE_PATH
    );
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
            | "/membership/task-delegate"
            | "/membership/task-delegate/scope"
            | "/membership/task-delegate/outbound-assignment"
            | "/membership/task-delegate/outbound"
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
    let internal_route = matches!(
        req_path.as_str(),
        "/health"
            | "/skill-mutation-audit"
            | "/trust-decision-once"
            | "/webchat/handoff/mint"
            | "/webchat/runtime-status"
    );
    let webchat_mint_route = req.path == "/webchat/handoff/mint";
    let webchat_status_route = req.path == "/webchat/runtime-status";
    if req.method != "POST"
        || !(membership_route
            || internal_route
            || state.audit_routes_enabled && (audit_route || chat_route || gui_chat_route))
    {
        let _ = stream
            .write_all(http_response(404, "not found").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    // Layer 2 — constant-time bearer verification before applying the
    // source-wide cooldown. Every audit-RPC client is kernel-attested local, so all
    // users share the same source key. A bad local client must not be able to
    // lock a valid CLI/GUI/Skill bearer out of its mandatory audit path.
    // Auth failures are NOT WAL-recorded (avoids a forged-frame paradox + WAL
    // spam).
    let now = std::time::Instant::now();
    let ok = req
        .bearer
        .as_deref()
        .is_some_and(|t| constant_time_token_eq(t, &state.token));
    if ok {
        state.cooldown.record_success(source);
    } else if state.cooldown.is_locked(source, now) {
        let _ = stream
            .write_all(http_response(429, "auth cooldown active").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    } else {
        state.cooldown.record_failure(source, now);
        let _ = stream
            .write_all(http_response(401, "unauthorized").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    if gui_chat_route {
        return handle_gui_chat_route(stream, state, req.path.as_str(), &req.body).await;
    }
    if webchat_mint_route {
        return handle_webchat_handoff_mint(stream, state).await;
    }
    if webchat_status_route {
        return handle_webchat_runtime_status(stream, state).await;
    }

    if chat_route {
        let request = match serde_json::from_slice::<super::DaemonPlainChatRequest>(&req.body) {
            Ok(request) => request,
            Err(_) => {
                let _ = stream
                    .write_all(http_response(422, "invalid_daemon_plain_chat_request").as_bytes())
                    .await;
                let _ = stream.shutdown().await;
                return Ok(ConnectionOutcome::Complete);
            }
        };
        if let Err(reason) = super::validate_daemon_plain_chat_request(&request) {
            let _ = stream
                .write_all(http_response(422, reason).as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(ConnectionOutcome::Complete);
        }
        return Ok(ConnectionOutcome::ChatAdmitted { stream, request });
    }

    if req_path == "/health" {
        let _ = stream
            .write_all(http_response_json(200, "{\"ok\":true}").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    if req_path == "/trust-decision-once" {
        let response = handle_trust_decision_once(state, home, &req.body).await;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    #[cfg(feature = "cluster")]
    if req_path.starts_with("/membership/") {
        if req_path == "/membership/task-delegate/outbound" {
            let Some(dispatcher) = state.outbound_task_delegate.as_ref().cloned() else {
                let _ = stream
                    .write_all(
                        http_response(503, "outbound task delegation unavailable").as_bytes(),
                    )
                    .await;
                let _ = stream.shutdown().await;
                return Ok(ConnectionOutcome::Complete);
            };
            let request = serde_json::from_slice::<
                crate::cluster::runtime_supervisor::OutboundTaskDelegateDispatchRequest,
            >(&req.body)
            .context("invalid outbound task delegation body")?;
            let result = tokio::task::spawn_blocking(move || dispatcher.dispatch(&request))
                .await
                .map_err(|e| anyhow::anyhow!("outbound task delegation worker failed: {e}"))?;
            let (status, body) = match result {
                Ok(value) => (200, serde_json::to_string(&value)?),
                Err(error) => (
                    422,
                    serde_json::json!({"error":format!("{error:#}")}).to_string(),
                ),
            };
            let _ = stream
                .write_all(http_response_json(status, &body).as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(ConnectionOutcome::Complete);
        }
        let Some(controller) = state.membership.as_ref().cloned() else {
            let _ = stream
                .write_all(http_response(503, "membership authority unavailable").as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(ConnectionOutcome::Complete);
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
        return Ok(ConnectionOutcome::Complete);
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
        return Ok(ConnectionOutcome::Complete);
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
        return Ok(ConnectionOutcome::Complete);
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
        return Ok(ConnectionOutcome::Complete);
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
        return Ok(ConnectionOutcome::Complete);
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
            return Ok(ConnectionOutcome::Complete);
        }
    };

    if req_path == "/skill-mutation-audit"
        && !(event_type == EVENT_TYPE_EXTENDED
            && matches!(
                ExtendedSubtype::from_u8(event_subtype),
                Some(
                    ExtendedSubtype::SkillInstallIntent
                        | ExtendedSubtype::SkillInstallResult
                        | ExtendedSubtype::SkillRemovalIntent
                        | ExtendedSubtype::SkillRemovalResult
                        | ExtendedSubtype::SkillAuthorityDecision
                )
            ))
    {
        emit_reject(state, "internal_skill_audit_identity_not_allowed").await;
        let _ = stream
            .write_all(http_response(422, "internal_skill_audit_identity_not_allowed").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

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
        return Ok(ConnectionOutcome::Complete);
    }

    if let Err(error) =
        validate_code_map_result_prepared_payload(event_type, event_subtype, &payload)
    {
        emit_reject(state, "invalid_code_map_result_receipt").await;
        let _ = stream
            .write_all(http_response(400, &format!("{error:#}")).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    // Version-two decisions have a durable operation identity. Only the
    // writer-owned once transaction may append them; generic /audit cannot
    // race that transaction or bypass its exact-descriptor conflict check.
    if event_type == EVENT_TYPE_EXTENDED && event_subtype == ExtendedSubtype::TrustDecision as u8 {
        let legacy =
            crate::permissions::trust_ledger::TrustEvent::decode(&payload).is_ok_and(|event| {
                event.schema_version == crate::permissions::trust_ledger::TRUST_EVENT_SCHEMA_VERSION
            });
        if !legacy {
            emit_reject(state, "trust_decision_requires_typed_once_route").await;
            let _ = stream
                .write_all(
                    http_response(422, "trust_decision_requires_typed_once_route").as_bytes(),
                )
                .await;
            let _ = stream.shutdown().await;
            return Ok(ConnectionOutcome::Complete);
        }
    }

    // Authority frames are scanned globally and authenticated before their
    // Skill id is inspected. Reject malformed or unauthenticated ingress
    // before append so one local request cannot poison unrelated Skills.
    if let Err(error) =
        authenticate_skill_authority_ingress(home, event_type, event_subtype, &payload).await
    {
        emit_reject(state, "invalid_skill_authority_binding").await;
        let _ = stream
            .write_all(http_response(400, &format!("{error:#}")).as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    // Skill mutation intent/result payloads carry a deterministic audit id.
    // Serialize identical deliveries through the daemon so a client whose
    // response was cancelled after the fsynced append cannot race a retry into
    // a second frame. A conflicting payload under the same id fails closed.
    let skill_dedup = match skill_audit_dedup_binding(event_type, event_subtype, &payload) {
        Ok(binding) => binding,
        Err(error) => {
            emit_reject(state, "invalid_skill_audit_binding").await;
            let _ = stream
                .write_all(http_response(400, &format!("{error:#}")).as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(ConnectionOutcome::Complete);
        }
    };
    if let Some((dedup_key, payload_sha256)) = skill_dedup {
        match append_skill_audit_idempotently(
            state.writer.clone(),
            event_type,
            event_subtype,
            payload,
            dedup_key,
            payload_sha256,
        )
        .await
        {
            Ok(SkillAuditAppendOutcome::Appended(offset)) => {
                notify_runtime_authority_transition_after_ack(home, event_type, event_subtype);
                emit_accept(state, event_type, event_subtype).await;
                let body = format!("{{\"ok\":true,\"offset\":{offset}}}");
                let _ = stream
                    .write_all(http_response_json(200, &body).as_bytes())
                    .await;
            }
            Ok(SkillAuditAppendOutcome::Duplicate) => {
                notify_runtime_authority_transition_after_ack(home, event_type, event_subtype);
                let body = "{\"ok\":true,\"duplicate\":true}";
                let _ = stream
                    .write_all(http_response_json(200, body).as_bytes())
                    .await;
            }
            Ok(SkillAuditAppendOutcome::Conflict) => {
                emit_reject(state, "skill_audit_id_conflict").await;
                let _ = stream
                    .write_all(http_response(409, "skill audit id conflict").as_bytes())
                    .await;
            }
            Ok(SkillAuditAppendOutcome::CapacityReached) => {
                let _ = stream
                    .write_all(http_response(503, "skill audit dedup capacity reached").as_bytes())
                    .await;
            }
            Err(error) => {
                let _ = stream
                    .write_all(http_response(500, &format!("append failed: {error:#}")).as_bytes())
                    .await;
            }
        }
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    }

    // Forward the frame into the daemon's single writer.
    let header = crate::wal::HeaderBuilder::new(event_type, &payload)
        .event_subtype(event_subtype)
        .build();
    let append = if event_type == EVENT_TYPE_EXTENDED
        && event_subtype == ExtendedSubtype::TrustDecision as u8
    {
        state.writer.append_authenticated(header, payload).await
    } else {
        state.writer.append(header, payload).await
    };
    match append {
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
    Ok(ConnectionOutcome::Complete)
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
        "/membership/task-delegate" => {
            let request: crate::cluster::membership::TaskDelegateAssignmentRequest =
                serde_json::from_slice(body).context("invalid task delegate assignment body")?;
            Ok(serde_json::to_value(
                controller.set_task_delegate_assignment(&request)?,
            )?)
        }
        "/membership/task-delegate/scope" => {
            let request: crate::cluster::membership::TaskDelegateScopedAssignmentRequest =
                serde_json::from_slice(body)
                    .context("invalid scoped task delegate assignment body")?;
            Ok(serde_json::to_value(
                controller.set_task_delegate_scoped_assignment(&request)?,
            )?)
        }
        "/membership/task-delegate/outbound-assignment" => {
            let request: crate::cluster::membership::TaskDelegateOutboundAssignmentRequest =
                serde_json::from_slice(body)
                    .context("invalid outbound task delegate assignment body")?;
            Ok(serde_json::to_value(
                controller.set_task_delegate_outbound_assignment(&request)?,
            )?)
        }
        _ => unreachable!("membership route allowlisted"),
    }
}

async fn handle_trust_decision_once(state: &AuditRpcState, home: &Path, body: &[u8]) -> String {
    use crate::permissions::trust_ledger::{TrustDecisionOnceError, TrustDecisionOnceOutcome};

    let request = match serde_json::from_slice::<super::TrustDecisionOnceRequest>(body) {
        Ok(request) if request.schema_version == 1 && request.descriptor.validate().is_ok() => {
            request
        }
        _ => return http_response(422, "invalid_trust_admission_descriptor"),
    };
    // The writer owns accepted work after this connection's timeout or loss.
    // Its reply is released only after lookup or a marker-covered append has
    // reached a terminal result; never emit ACCEPT for an unknown outcome.
    let outcome = state
        .writer
        .append_trust_decision_once(home, request.descriptor)
        .await;
    let outcome = match outcome {
        Ok(TrustDecisionOnceOutcome::AppendedExact) => {
            emit_accept(
                state,
                EVENT_TYPE_EXTENDED,
                ExtendedSubtype::TrustDecision as u8,
            )
            .await;
            super::TrustDecisionOnceWireOutcome::AppendedExact
        }
        Ok(TrustDecisionOnceOutcome::ExistingExact) => {
            super::TrustDecisionOnceWireOutcome::ExistingExact
        }
        Err(TrustDecisionOnceError::Conflict) => {
            return http_response(409, "trust_admission_conflict");
        }
        Err(TrustDecisionOnceError::Duplicate) => {
            return http_response(409, "trust_admission_duplicate");
        }
        Err(TrustDecisionOnceError::Indeterminate) => {
            return http_response(503, "trust_admission_indeterminate");
        }
    };
    match serde_json::to_string(&super::TrustDecisionOnceResponse {
        schema_version: 1,
        outcome,
    }) {
        Ok(body) => http_response_json(200, &body),
        Err(_) => http_response(503, "trust_admission_response_unavailable"),
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

/// W41 sealed v1 dispatch. Parsing, bearer auth and request cap happened under
/// the listener's ordinary five-second pre-admission deadline. Each route
/// validates after `deny_unknown_fields` decoding and again validates its
/// response before it crosses the bridge client boundary. Attach alone hands
/// the authenticated stream to the runtime after the basic cursor shape check;
/// its capability-record upper bound is checked by the runtime before replay.
async fn handle_gui_chat_route(
    mut stream: super::transport::AuditStream,
    state: &AuditRpcState,
    path: &str,
    body: &[u8],
) -> Result<ConnectionOutcome> {
    let Some(runtime) = state.gui_chat_runtime.as_ref().cloned() else {
        let _ = stream
            .write_all(http_response(503, "gui chat runtime unavailable").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    };
    macro_rules! response {
        ($request:ty, $parse:path, $call:ident, $validate:path) => {{
            let request = match serde_json::from_slice::<$request>(body) {
                Ok(request) => request,
                Err(_) => {
                    let _ = stream
                        .write_all(http_response(422, "invalid_gui_chat_request").as_bytes())
                        .await;
                    let _ = stream.shutdown().await;
                    return Ok(ConnectionOutcome::Complete);
                }
            };
            if $parse(&request).is_err() {
                let _ = stream
                    .write_all(http_response(422, "invalid_gui_chat_request").as_bytes())
                    .await;
                let _ = stream.shutdown().await;
                return Ok(ConnectionOutcome::Complete);
            }
            match runtime.$call(request).await {
                Ok(reply) if $validate(&reply).is_ok() => {
                    let body = serde_json::to_string(&reply).context("encode GUI chat reply")?;
                    let _ = stream
                        .write_all(http_response_json(200, &body).as_bytes())
                        .await;
                }
                Ok(_) => {
                    let _ = stream
                        .write_all(http_response(500, "invalid_gui_chat_response").as_bytes())
                        .await;
                }
                Err(error) => {
                    tracing::warn!(?error, "GUI chat route refused");
                    let _ = stream
                        .write_all(http_response(503, "gui_chat_unavailable").as_bytes())
                        .await;
                }
            }
            let _ = stream.shutdown().await;
            Ok(ConnectionOutcome::Complete)
        }};
    }
    match path {
        gui::GUI_CHAT_V1_CONSENT_PREFLIGHT_PATH => response!(
            gui::GuiChatPreflightRequest,
            gui::validate_preflight_request,
            preflight,
            gui::validate_preflight_response
        ),
        gui::GUI_CHAT_V1_CONSENT_DECIDE_PATH => response!(
            gui::GuiChatConsentDecisionRequest,
            gui::validate_decide_request,
            decide,
            gui::validate_decide_response
        ),
        gui::GUI_CHAT_V1_START_PATH => response!(
            gui::GuiChatStartRequest,
            gui::validate_start_request,
            start,
            gui::validate_start_response
        ),
        gui::GUI_CHAT_V1_ATTACH_EXCHANGE_PATH => response!(
            gui::GuiChatAttachExchangeRequest,
            gui::validate_attach_exchange_request,
            exchange_attach,
            gui::validate_attach_exchange_response
        ),
        gui::GUI_CHAT_V1_CANCEL_PATH => response!(
            gui::GuiChatCancelRequest,
            gui::validate_cancel_request,
            cancel,
            gui::validate_cancel_response
        ),
        gui::GUI_CHAT_V1_STATUS_PATH => response!(
            gui::GuiChatStatusRequest,
            gui::validate_status_request,
            status,
            gui::validate_status_response
        ),
        gui::GUI_CHAT_V1_ACTIVE_PATH => response!(
            gui::GuiChatActiveRequest,
            gui::validate_active_request,
            active,
            gui::validate_active_response
        ),
        gui::GUI_CHAT_V1_ATTACH_PATH => {
            let request = match serde_json::from_slice::<gui::GuiChatAttachRequest>(body) {
                Ok(request) => request,
                Err(_) => {
                    let _ = stream
                        .write_all(http_response(422, "invalid_gui_chat_attach").as_bytes())
                        .await;
                    let _ = stream.shutdown().await;
                    return Ok(ConnectionOutcome::Complete);
                }
            };
            // The runtime owns the authenticated capability registry and uses
            // its stored high-water mark as the real cursor bound.
            if gui::validate_attach_request(&request, u64::MAX).is_err() {
                let _ = stream
                    .write_all(http_response(422, "invalid_gui_chat_attach").as_bytes())
                    .await;
                let _ = stream.shutdown().await;
                return Ok(ConnectionOutcome::Complete);
            }
            Ok(ConnectionOutcome::GuiChatAttachAdmitted { stream, request })
        }
        _ => {
            let _ = stream
                .write_all(http_response(404, "not found").as_bytes())
                .await;
            let _ = stream.shutdown().await;
            Ok(ConnectionOutcome::Complete)
        }
    }
}
async fn handle_webchat_runtime_status(
    mut stream: super::transport::AuditStream,
    state: &AuditRpcState,
) -> Result<ConnectionOutcome> {
    let Some(webchat) = state.webchat.as_ref() else {
        let _ = stream
            .write_all(http_response(503, "webchat unavailable").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    };
    let body = serde_json::to_string(&webchat.runtime_status())
        .context("encode webchat runtime status")?;
    let _ = stream
        .write_all(http_response_json(200, &body).as_bytes())
        .await;
    let _ = stream.shutdown().await;
    Ok(ConnectionOutcome::Complete)
}
async fn handle_webchat_handoff_mint(
    mut stream: super::transport::AuditStream,
    state: &AuditRpcState,
) -> Result<ConnectionOutcome> {
    let Some(webchat) = state.webchat.as_ref().cloned() else {
        let _ = stream
            .write_all(http_response(503, "webchat unavailable").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(ConnectionOutcome::Complete);
    };
    match webchat.mint_handoff().await {
        Ok(reply) => {
            let body = serde_json::to_string(&reply).context("encode webchat handoff")?;
            let _ = stream
                .write_all(http_response_json(200, &body).as_bytes())
                .await;
        }
        Err(_) => {
            let _ = stream
                .write_all(http_response(503, "webchat handoff unavailable").as_bytes())
                .await;
        }
    }
    let _ = stream.shutdown().await;
    Ok(ConnectionOutcome::Complete)
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
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
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
