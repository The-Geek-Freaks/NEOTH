//! Scoped, generation-bound Dream JSONL to Obsidian synchronization.
//!
//! The handler owns admission and durable terminal evidence; the bounded
//! reader/writer itself lives in `daemon::dreaming_obsidian`.

use chrono::NaiveDate;
use serde::Deserialize;

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::daemon::dreaming_obsidian::{CheckedDreamSyncOutcome, DreamSyncDurability};

const DEFAULT_SUBDIR: &str = "NEOTH-sessions";
const EFFECT: &str = "n8n Dream Obsidian sync";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DreamSyncRequest {
    day: String,
}

/// Run a strictly scoped Dream-day sync. The blocking worker owns the accepted
/// generation lease until it has durably recorded a terminal result, even if
/// its awaiting HTTP future is dropped.
pub(super) async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: DreamSyncRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    if !canonical_day(&request.day) {
        return invalid_request();
    }

    let accepted = state.reload_controller.accepted_snapshot();
    let config = accepted.config();
    if !config.dreaming.enabled
        || !crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy)
    {
        return HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            "dream_obsidian_sync_disabled",
            "enable Dream scheduling under an autonomy level that permits scheduled work",
        );
    }
    let Some(vault) = config
        .obsidian_vault
        .as_deref()
        .filter(|vault| !vault.trim().is_empty())
    else {
        return HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "dream_obsidian_sync_vault_not_configured",
            "configure this instance's Obsidian vault before syncing Dream output",
        );
    };
    let subdir = config
        .obsidian_subdir
        .as_deref()
        .filter(|subdir| !subdir.trim().is_empty())
        .unwrap_or(DEFAULT_SUBDIR);
    let lease = match accepted.acquire_dream_commit(EFFECT) {
        Ok(lease) => lease,
        Err(_) => return HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            "dream_obsidian_sync_generation_retired",
            "reload or shutdown retired this Dream generation before sync admission",
        ),
    };

    let home = state.home.clone();
    let vault = std::path::PathBuf::from(vault);
    let subdir = subdir.to_owned();
    let day = request.day;
    let writer = state.writer.clone();
    let runtime = tokio::runtime::Handle::current();
    let admission = audit_payload(ctx, accepted.epoch(), &day, "admission", None);
    let terminal_context = TerminalContext {
        request_id: ctx.request_id.clone(),
        source_ip: ctx.source_ip.clone(),
        caller: ctx.caller.clone(),
        epoch: accepted.epoch(),
        day: day.clone(),
    };
    let worker = tokio::task::spawn_blocking(move || {
        run_worker(
            lease,
            admission,
            terminal_context,
            |payload| append_audit(&runtime, &writer, payload),
            || crate::daemon::dreaming_obsidian::sync_day_checked(&home, &vault, &subdir, &day),
        )
    });

    match worker.await {
        Ok(WorkerResult::Completed {
            day,
            written,
            dream_count,
            bytes_written,
            durability,
            epoch,
            request_id,
        }) => {
            HandlerOutcome::ok_json(serde_json::json!({
                "day": day,
                "written": written,
                "dream_count": dream_count,
                "bytes_written": bytes_written,
                "durability": durability,
                "accepted_epoch": epoch,
                "request_id": request_id,
            }))
        }
        Ok(WorkerResult::AdmissionUnavailable) => unavailable(
            "dream_obsidian_sync_audit_unavailable",
            "durable Dream sync admission could not be recorded; no sync was started",
        ),
        Ok(WorkerResult::Failed) => unavailable(
            "dream_obsidian_sync_failed",
            "Dream sync returned an error after admission; inspect terminal evidence and do not automatically retry because filesystem outcome may be unknown",
        ),
        Ok(WorkerResult::OutcomeUnknown) | Err(_) => unavailable(
            "dream_obsidian_sync_outcome_unknown",
            "Dream sync terminal evidence is unavailable; do not assume rollback or retry safety",
        ),
    }
}

/// The lease enters before admission and is released only after a terminal
/// receipt attempt. Keeping this narrow runner injectable makes failure and
/// detached-client tests exercise that ordering without a second WAL service.
fn run_worker(
    lease: crate::config::reload::DreamCommitLease,
    admission: Vec<u8>,
    terminal_context: TerminalContext,
    mut append: impl FnMut(Vec<u8>) -> Result<(), ()>,
    sync: impl FnOnce() -> anyhow::Result<CheckedDreamSyncOutcome>,
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
                    day: outcome.day,
                    written: outcome.written,
                    dream_count: outcome.dream_count,
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

fn canonical_day(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || (*byte).is_ascii_digit())
        && NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .is_ok_and(|day| day.format("%Y-%m-%d").to_string() == value)
}

fn invalid_request() -> HandlerOutcome {
    HandlerOutcome::error(
        ApiErrorCode::BadRequest,
        "dream_obsidian_sync_request_invalid",
        "supply only a canonical Dream day in YYYY-MM-DD form",
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
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_N8N_REQUEST,
        &payload,
    )
    .build();
    runtime
        .block_on(writer.append(header, payload))
        .map(|_| ())
        .map_err(|_| ())
}

fn audit_payload(
    ctx: &ApiRequestCtx,
    epoch: u64,
    day: &str,
    phase: &str,
    outcome: Option<&CheckedDreamSyncOutcome>,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "kind": "n8n_dream_obsidian_sync",
        "phase": phase,
        "request_id": ctx.request_id,
        "source_ip": ctx.source_ip,
        "caller": ctx.caller,
        "accepted_epoch": epoch,
        "day": day,
        "written": outcome.map(|item| item.written),
        "dream_count": outcome.map(|item| item.dream_count),
        "bytes_written": outcome.map(|item| item.bytes_written),
        "durability": outcome.map(|item| item.durability),
    })).expect("fixed Dream audit payload serializes")
}

struct TerminalContext {
    request_id: String,
    source_ip: String,
    caller: crate::n8n_api::server::ApiCaller,
    epoch: u64,
    day: String,
}

impl TerminalContext {
    fn payload(
        &self,
        phase: &str,
        outcome: Option<&CheckedDreamSyncOutcome>,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "n8n_dream_obsidian_sync",
            "phase": phase,
            "request_id": self.request_id,
            "source_ip": self.source_ip,
            "caller": self.caller,
            "accepted_epoch": self.epoch,
            "day": self.day,
            "written": outcome.map(|item| item.written),
            "dream_count": outcome.map(|item| item.dream_count),
            "bytes_written": outcome.map(|item| item.bytes_written),
            "durability": outcome.map(|item| item.durability),
        })).expect("fixed Dream audit payload serializes")
    }
}

enum WorkerResult {
    Completed {
        day: String,
        written: bool,
        dream_count: usize,
        bytes_written: usize,
        durability: DreamSyncDurability,
        epoch: u64,
        request_id: String,
    },
    AdmissionUnavailable,
    Failed,
    OutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    fn controller() -> Arc<crate::config::reload::ReloadController> {
        let mut config = crate::config::FreedomConfig::default();
        config.dreaming.enabled = true;
        config.autonomy = crate::permissions::AutonomyLevel::Standard;
        Arc::new(crate::config::reload::ReloadController::new(
            config,
            PathBuf::from("dream-handler-test-freedom.yaml"),
        ))
    }

    fn lease(
        controller: &crate::config::reload::ReloadController,
    ) -> crate::config::reload::DreamCommitLease {
        controller
            .accepted_snapshot()
            .acquire_dream_commit("Dream handler test")
            .unwrap()
    }

    fn terminal_context() -> TerminalContext {
        TerminalContext {
            request_id: "dream-handler-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            caller: crate::n8n_api::server::ApiCaller::MasterToken,
            epoch: 0,
            day: "2026-09-24".to_owned(),
        }
    }

    fn outcome() -> CheckedDreamSyncOutcome {
        CheckedDreamSyncOutcome {
            day: "2026-09-24".to_owned(),
            written: true,
            target_path: PathBuf::from("C:/private-vault/Dreams/2026-09-24.md"),
            dream_count: 1,
            bytes_written: 24,
            durability: DreamSyncDurability::PublishedAndSynced,
        }
    }

    #[test]
    fn canonical_day_rejects_extended_years_and_non_ascii_digits() {
        assert!(canonical_day("2026-09-24"));
        for invalid in [
            "+2026-09-24",
            "02026-09-24",
            "٢٠٢٦-٠٩-٢٤",
            "2026-9-24",
        ] {
            assert!(!canonical_day(invalid), "{invalid}");
        }
    }

    #[test]
    fn admission_audit_failure_starts_no_sync_or_filesystem_effect() {
        let controller = controller();
        let sync_calls = AtomicUsize::new(0);
        let result = run_worker(
            lease(&controller),
            vec![1],
            terminal_context(),
            |_| Err(()),
            || {
                sync_calls.fetch_add(1, Ordering::SeqCst);
                Ok(outcome())
            },
        );
        assert!(matches!(result, WorkerResult::AdmissionUnavailable));
        assert_eq!(sync_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn terminal_audit_failure_returns_outcome_unknown_after_sync() {
        let controller = controller();
        let append_calls = AtomicUsize::new(0);
        let sync_calls = AtomicUsize::new(0);
        let result = run_worker(
            lease(&controller),
            vec![1],
            terminal_context(),
            |_| {
                let call = append_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    Ok(())
                } else {
                    Err(())
                }
            },
            || {
                sync_calls.fetch_add(1, Ordering::SeqCst);
                Ok(outcome())
            },
        );
        assert!(matches!(result, WorkerResult::OutcomeUnknown));
        assert_eq!(sync_calls.load(Ordering::SeqCst), 1);
        assert_eq!(append_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn detached_handler_worker_finishes_terminal_receipt_before_lease_drain() {
        let controller = controller();
        let (sync_started_tx, sync_started_rx) = mpsc::sync_channel(1);
        let (release_sync_tx, release_sync_rx) = mpsc::sync_channel(1);
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(1);
        let (retired_tx, retired_rx) = mpsc::sync_channel(1);
        let append_calls = Arc::new(AtomicUsize::new(0));
        let worker_append_calls = Arc::clone(&append_calls);
        let worker_lease = lease(&controller);
        let worker = tokio::task::spawn_blocking(move || {
            run_worker(
                worker_lease,
                vec![1],
                terminal_context(),
                move |_| {
                    if worker_append_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                        terminal_tx.send(()).unwrap();
                    }
                    Ok(())
                },
                move || {
                    sync_started_tx.send(()).unwrap();
                    release_sync_rx.recv().unwrap();
                    Ok(outcome())
                },
            )
        });
        drop(worker); // Equivalent to a disconnected HTTP waiter: Tokio detaches this worker.
        sync_started_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let retiring_controller = Arc::clone(&controller);
        let retiring = std::thread::spawn(move || {
            retiring_controller.retire_generation_effect_runtime();
            retired_tx.send(()).unwrap();
        });
        let retirement_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while controller
            .accepted_snapshot()
            .acquire_dream_commit("observe closed admission")
            .is_ok()
        {
            assert!(std::time::Instant::now() < retirement_deadline);
            std::thread::yield_now();
        }
        assert!(matches!(retired_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        release_sync_tx.send(()).unwrap();
        terminal_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        retired_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        retiring.join().unwrap();
        assert_eq!(append_calls.load(Ordering::SeqCst), 2);
        assert!(controller
            .accepted_snapshot()
            .acquire_dream_commit("retired handler test")
            .is_err());
    }
}
