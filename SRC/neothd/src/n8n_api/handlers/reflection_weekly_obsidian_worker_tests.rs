#![cfg(test)]

//! Worker settlement ordering for the weekly Obsidian handler.

use std::sync::Arc;

use super::*;
use crate::config::FreedomConfig;

fn controller() -> Arc<crate::config::reload::ReloadController> {
    let home = crate::test_env::canonical_tempdir().unwrap();
    Arc::new(crate::config::reload::ReloadController::new(FreedomConfig::default(), home.path().join("freedom.yaml")))
}

fn context() -> TerminalContext {
    TerminalContext { request_id: "weekly-worker-request".into(), source_ip: "127.0.0.1".into(), caller: crate::n8n_api::server::ApiCaller::MasterToken, epoch: 0, week: "2026-W21".into() }
}

fn outcome() -> crate::reflection::weekly_obsidian::CheckedReflectionSyncOutcome {
    crate::reflection::weekly_obsidian::CheckedReflectionSyncOutcome { iso_week_tag: "2026-W21".into(), written: false, target_path: std::path::PathBuf::from("C:\\weekly-note"), reflection_count: 0, bytes_written: 0, durability: crate::reflection::weekly_obsidian::ReflectionSyncDurability::NotWritten }
}

#[test]
fn weekly_worker_admission_failure_never_starts_effect() {
    let controller = controller(); let lease = controller.accepted_snapshot().acquire_egress_leaf().unwrap();
    let result = run_worker(lease, b"admission".to_vec(), context(), |_| Err(()), || -> anyhow::Result<_> { panic!("sync must not run after admission failure") });
    assert!(matches!(result, WorkerResult::AdmissionUnavailable));
}

#[test]
fn weekly_worker_terminal_audit_failure_is_outcome_unknown() {
    let controller = controller(); let lease = controller.accepted_snapshot().acquire_egress_leaf().unwrap(); let mut calls = 0;
    let result = run_worker(lease, b"admission".to_vec(), context(), |_| { calls += 1; if calls == 1 { Ok(()) } else { Err(()) } }, || Ok(outcome()));
    assert!(matches!(result, WorkerResult::OutcomeUnknown));
}

#[tokio::test]
async fn detached_weekly_worker_holds_egress_lease_through_terminal_audit_and_reload() {
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    let root = crate::test_env::canonical_tempdir().unwrap(); let source = root.path().join("freedom.yaml"); let initial = FreedomConfig::default(); std::fs::write(&source, serde_yaml::to_string(&initial).unwrap()).unwrap();
    let controller = Arc::new(crate::config::reload::ReloadController::new(initial.clone(), source.clone())); let accepted = controller.accepted_snapshot(); let lease = accepted.acquire_egress_leaf().unwrap();
    let (sync_started_tx, sync_started_rx) = sync_channel(0); let (sync_release_tx, sync_release_rx) = sync_channel(0); let (terminal_started_tx, terminal_started_rx) = sync_channel(0); let (terminal_release_tx, terminal_release_rx) = sync_channel(0); let (done_tx, done_rx) = sync_channel(1);
    let handle = tokio::task::spawn_blocking(move || { let mut appends = 0; let result = run_worker(lease, b"admission".to_vec(), context(), |_| { appends += 1; if appends == 1 { Ok(()) } else { terminal_started_tx.send(()).unwrap(); terminal_release_rx.recv_timeout(Duration::from_secs(10)).unwrap(); Ok(()) } }, || { sync_started_tx.send(()).unwrap(); sync_release_rx.recv_timeout(Duration::from_secs(10)).unwrap(); Ok(outcome()) }); done_tx.send(result).unwrap(); }); drop(handle);
    sync_started_rx.recv_timeout(Duration::from_secs(10)).unwrap(); let mut changed = initial; changed.review_gate_enabled = !changed.review_gate_enabled; std::fs::write(&source, serde_yaml::to_string(&changed).unwrap()).unwrap(); let reloader = Arc::clone(&controller); let reload = std::thread::spawn(move || reloader.try_reload());
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while accepted.acquire_egress_leaf().is_ok() {
        assert!(std::time::Instant::now() < deadline, "reload did not retire admission");
        std::thread::yield_now();
    }
    sync_release_tx.send(()).unwrap(); terminal_started_rx.recv_timeout(Duration::from_secs(10)).unwrap(); assert!(!reload.is_finished(), "reload must wait while terminal audit holds the egress lease"); assert!(Arc::ptr_eq(&controller.accepted_snapshot(), &accepted));
    terminal_release_tx.send(()).unwrap(); assert!(matches!(done_rx.recv_timeout(Duration::from_secs(10)).unwrap(), WorkerResult::Completed { .. })); assert!(matches!(reload.join().unwrap().unwrap(), crate::config::reload::ReloadResult::Reloaded { .. })); assert!(!Arc::ptr_eq(&controller.accepted_snapshot(), &accepted));
}
