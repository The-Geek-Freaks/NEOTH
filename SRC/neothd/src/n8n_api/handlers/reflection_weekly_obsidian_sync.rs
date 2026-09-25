//! Scoped, generation-bound weekly reflection JSONL to Obsidian synchronization.
//!
//! The handler owns admission and durable terminal evidence; the bounded
//! reader/writer itself lives in `reflection::weekly_obsidian`.

use serde::Deserialize;

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::reflection::weekly_obsidian::{CheckedReflectionSyncOutcome, ReflectionSyncDurability};

const DEFAULT_SUBDIR: &str = "NEOTH-sessions";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReflectionSyncRequest {
    week: String,
}

/// Sync one archived ISO week. The blocking worker owns the accepted
/// generation lease until it has durably recorded a terminal result, even if
/// its awaiting HTTP future is dropped.
pub(super) async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: ReflectionSyncRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    if !canonical_week(&request.week) {
        return invalid_request();
    }

    let accepted = state.reload_controller.accepted_snapshot();
    let config = accepted.config();
    let Some(vault) = config
        .obsidian_vault
        .as_deref()
        .filter(|vault| !vault.trim().is_empty())
    else {
        return HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "reflection_weekly_obsidian_sync_vault_not_configured",
            "configure this instance's Obsidian vault before syncing weekly reflection output",
        );
    };
    let subdir = config
        .obsidian_subdir
        .as_deref()
        .filter(|subdir| !subdir.trim().is_empty())
        .unwrap_or(DEFAULT_SUBDIR);
    let lease = match accepted.acquire_egress_leaf() {
        Ok(lease) => lease,
        Err(_) => {
            return HandlerOutcome::error(
                ApiErrorCode::PermissionDenied,
                "reflection_weekly_obsidian_sync_generation_retired",
                "reload or shutdown retired this weekly reflection generation before sync admission",
            );
        }
    };

    let home = state.home.clone();
    let vault = std::path::PathBuf::from(vault);
    let subdir = subdir.to_owned();
    let week = request.week;
    let writer = state.writer.clone();
    let runtime = tokio::runtime::Handle::current();
    let admission = audit_payload(ctx, accepted.epoch(), &week, "admission", None);
    let terminal_context = TerminalContext {
        request_id: ctx.request_id.clone(),
        source_ip: ctx.source_ip.clone(),
        caller: ctx.caller.clone(),
        epoch: accepted.epoch(),
        week: week.clone(),
    };
    let worker = tokio::task::spawn_blocking(move || {
        run_worker(
            lease,
            admission,
            terminal_context,
            |payload| append_audit(&runtime, &writer, payload),
            || crate::reflection::weekly_obsidian::sync_week_checked(&home, &vault, &subdir, &week),
        )
    });

    match worker.await {
        Ok(WorkerResult::Completed {
            week,
            written,
            reflection_count,
            bytes_written,
            durability,
            epoch,
            request_id,
        }) => HandlerOutcome::ok_json(serde_json::json!({
            "week": week,
            "written": written,
            "reflection_count": reflection_count,
            "bytes_written": bytes_written,
            "durability": durability,
            "accepted_epoch": epoch,
            "request_id": request_id,
        })),
        Ok(WorkerResult::AdmissionUnavailable) => unavailable(
            "reflection_weekly_obsidian_sync_audit_unavailable",
            "durable weekly reflection sync admission could not be recorded; no sync was started",
        ),
        Ok(WorkerResult::Failed) => unavailable(
            "reflection_weekly_obsidian_sync_failed",
            "weekly reflection sync returned an error after admission; inspect terminal evidence and do not automatically retry because filesystem outcome may be unknown",
        ),
        Ok(WorkerResult::OutcomeUnknown) | Err(_) => unavailable(
            "reflection_weekly_obsidian_sync_outcome_unknown",
            "weekly reflection sync terminal evidence is unavailable; do not assume rollback or retry safety",
        ),
    }
}

/// The lease enters before admission and is released only after a terminal
/// receipt attempt. Keeping this narrow runner injectable makes failure and
/// detached-client tests exercise that ordering without a second WAL service.
fn run_worker(
    lease: crate::config::reload::GenerationEffectLease,
    admission: Vec<u8>,
    terminal_context: TerminalContext,
    mut append: impl FnMut(Vec<u8>) -> Result<(), ()>,
    sync: impl FnOnce() -> anyhow::Result<CheckedReflectionSyncOutcome>,
) -> WorkerResult {
    let _lease = lease;
    if append(admission).is_err() {
        return WorkerResult::AdmissionUnavailable;
    }
    match sync() {
        Ok(outcome) => {
            let audit = terminal_context.payload("completed", Some(&outcome));
            if append(audit).is_err() {
                WorkerResult::OutcomeUnknown
            } else {
                WorkerResult::Completed {
                    week: outcome.iso_week_tag,
                    written: outcome.written,
                    reflection_count: outcome.reflection_count,
                    bytes_written: outcome.bytes_written,
                    durability: outcome.durability,
                    epoch: terminal_context.epoch,
                    request_id: terminal_context.request_id,
                }
            }
        }
        Err(_) => {
            // A general filesystem primitive error cannot prove that no
            // namespace publication happened. The durable failure receipt and
            // fixed HTTP hint therefore never claim that a retry is safe.
            if append(terminal_context.payload("failed", None)).is_err() {
                WorkerResult::OutcomeUnknown
            } else {
                WorkerResult::Failed
            }
        }
    }
}

fn canonical_week(value: &str) -> bool {
    crate::reflection::weekly_archive::validate_iso_week_tag(value).is_ok()
}

fn invalid_request() -> HandlerOutcome {
    HandlerOutcome::error(
        ApiErrorCode::BadRequest,
        "reflection_weekly_obsidian_sync_request_invalid",
        "supply only a canonical weekly reflection week in YYYY-Www form",
    )
}

fn unavailable(message: &'static str, hint: &'static str) -> HandlerOutcome {
    HandlerOutcome::error(ApiErrorCode::StoreUnavailable, message, hint)
}

fn append_audit(
    runtime: &tokio::runtime::Handle,
    writer: &crate::wal::writer::WalWriterHandle,
    payload: Vec<u8>,
) -> Result<(), ()> {
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_N8N_REQUEST, &payload)
            .build();
    runtime
        .block_on(writer.append(header, payload))
        .map(|_| ())
        .map_err(|_| ())
}

fn audit_payload(
    ctx: &ApiRequestCtx,
    epoch: u64,
    week: &str,
    phase: &str,
    outcome: Option<&CheckedReflectionSyncOutcome>,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "kind": "n8n_reflection_weekly_obsidian_sync",
        "phase": phase,
        "request_id": ctx.request_id,
        "source_ip": ctx.source_ip,
        "caller": ctx.caller,
        "accepted_epoch": epoch,
        "week": week,
        "written": outcome.map(|item| item.written),
        "reflection_count": outcome.map(|item| item.reflection_count),
        "bytes_written": outcome.map(|item| item.bytes_written),
        "durability": outcome.map(|item| item.durability),
    }))
    .expect("fixed weekly reflection audit payload serializes")
}

struct TerminalContext {
    request_id: String,
    source_ip: String,
    caller: crate::n8n_api::server::ApiCaller,
    epoch: u64,
    week: String,
}

impl TerminalContext {
    fn payload(&self, phase: &str, outcome: Option<&CheckedReflectionSyncOutcome>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "n8n_reflection_weekly_obsidian_sync",
            "phase": phase,
            "request_id": self.request_id,
            "source_ip": self.source_ip,
            "caller": self.caller,
            "accepted_epoch": self.epoch,
            "week": self.week,
            "written": outcome.map(|item| item.written),
            "reflection_count": outcome.map(|item| item.reflection_count),
            "bytes_written": outcome.map(|item| item.bytes_written),
            "durability": outcome.map(|item| item.durability),
        }))
        .expect("fixed weekly reflection audit payload serializes")
    }
}

enum WorkerResult {
    Completed {
        week: String,
        written: bool,
        reflection_count: usize,
        bytes_written: usize,
        durability: ReflectionSyncDurability,
        epoch: u64,
        request_id: String,
    },
    AdmissionUnavailable,
    Failed,
    OutcomeUnknown,
}

#[path = "reflection_weekly_obsidian_worker_tests.rs"]
mod tests;
