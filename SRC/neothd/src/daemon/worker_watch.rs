//! MONITOR-02 — real-time worker-task death detection.
//!
//! The daemon's long-running cron/worker loops (monitor, ecology, drift,
//! resource-watch, …) should NEVER finish on their own — a loop that returns
//! has panicked or exited unexpectedly. The HO-07 monitor cron only catches that
//! retroactively, via the `crash.log` scan (`0x49 CRASH_LOG_ALERT`); this watcher
//! polls each worker's [`AbortHandle::is_finished`] every interval and emits
//! `0x4D WORKER_DIED` the moment one dies, NAMING the task (lower latency + which-
//! task attribution).
//!
//! It holds only ABORT handles (cheap clones of the originals), so the daemon's
//! own shutdown-abort of the real `JoinHandle`s is entirely unaffected. The
//! caller aborts the returned watcher handle FIRST during shutdown, so the
//! deliberate abort of the watched workers never registers as a "death".

use std::time::Duration;

use tokio::task::{AbortHandle, JoinHandle};

use crate::wal::writer::WalWriterHandle;

/// One supervised worker: a static name + the task's abort handle (used here
/// only for `is_finished()` — the daemon retains the real `JoinHandle`).
pub struct WatchedWorker {
    pub name: &'static str,
    pub handle: AbortHandle,
}

impl WatchedWorker {
    pub fn new(name: &'static str, handle: AbortHandle) -> Self {
        Self { name, handle }
    }
}

/// Minimum poll interval — a dead worker is surfaced within this bound.
const WORKER_WATCH_FLOOR_SECS: u64 = 5;

/// Spawn the worker-watch loop. Returns `None` (no idle task) when `workers` is
/// empty. The caller MUST abort the returned handle before aborting the watched
/// workers during shutdown.
pub fn spawn_worker_watch(
    workers: Vec<WatchedWorker>,
    writer: WalWriterHandle,
    interval_secs: u64,
) -> Option<JoinHandle<()>> {
    if workers.is_empty() {
        return None;
    }
    let interval_secs = interval_secs.max(WORKER_WATCH_FLOOR_SECS);
    Some(tokio::spawn(async move {
        let mut alerted = vec![false; workers.len()];
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            scan_workers(&workers, &mut alerted, &writer).await;
        }
    }))
}

/// One poll pass: emit `0x4D WORKER_DIED` once for each worker that has finished
/// since the last pass. Split out (pure-ish over the inputs) so the death-detect
/// + once-per-worker dedup is unit-testable without the timing loop.
async fn scan_workers(workers: &[WatchedWorker], alerted: &mut [bool], writer: &WalWriterHandle) {
    for (i, w) in workers.iter().enumerate() {
        if !alerted[i] && w.handle.is_finished() {
            alerted[i] = true;
            emit_worker_died(writer, w.name).await;
        }
    }
}

/// Emit `0x4D WORKER_DIED`. Best-effort: a watcher that can't write its alert
/// logs + carries on (the next durable frame seals the chain).
async fn emit_worker_died(writer: &WalWriterHandle, worker: &str) {
    tracing::warn!(
        worker,
        "MONITOR-02: daemon worker task DIED unexpectedly (panic or early exit)"
    );
    let now = crate::time::now_unix_secs();
    let payload = match serde_json::to_vec(&serde_json::json!({ "worker": worker, "ts_unix": now }))
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize WORKER_DIED payload failed");
            return;
        }
    };
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_WORKER_DIED, &payload);
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WORKER_DIED WAL append failed (audit gap)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_workers_spawns_no_task() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) = crate::wal::writer::spawn(dir.path().join("000001.wal")).unwrap();
        assert!(spawn_worker_watch(Vec::new(), writer, 5).is_none());
        // `writer` was moved into + dropped by the None path → the task drains.
        let _ = join.await;
    }

    #[tokio::test]
    async fn scan_emits_once_per_dead_worker() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // A task that finishes immediately = a "dead" worker.
        let task = tokio::spawn(async {});
        let handle = task.abort_handle();
        task.await.unwrap();
        assert!(handle.is_finished());

        let workers = vec![WatchedWorker::new("test_worker", handle)];
        let mut alerted = vec![false; 1];
        scan_workers(&workers, &mut alerted, &writer).await;
        assert!(alerted[0], "a finished worker is flagged");
        // A second pass must NOT re-emit — once per worker.
        scan_workers(&workers, &mut alerted, &writer).await;

        drop(writer);
        let _ = join.await;
        let bytes = std::fs::read(&seg).unwrap();
        let f = crate::wal::frame::decode_frame(
            &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(
            f.header.event_type,
            crate::wal::events::EVENT_TYPE_WORKER_DIED
        );
        let v: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
        assert_eq!(v["worker"], "test_worker");
        // Exactly one WORKER_DIED (the dedup held). TESTDEBT-WAL-01: the
        // segment may still carry the writer's own `0x15` compaction marker,
        // so assert on the absence of a SECOND WORKER_DIED rather than on the
        // absence of any further frame — the original form would pass for the
        // wrong reason the moment WAL bookkeeping changes again.
        let mut cursor =
            crate::wal::segment_header::SEGMENT_HEADER_LEN + f.header.total_len as usize;
        let mut died_frames = 1;
        while let Ok(next) = crate::wal::frame::decode_frame(&bytes[cursor..]) {
            if next.header.event_type == crate::wal::events::EVENT_TYPE_WORKER_DIED {
                died_frames += 1;
            }
            cursor += next.header.total_len as usize;
        }
        assert_eq!(died_frames, 1, "only one WORKER_DIED frame must be written",);
    }

    #[tokio::test]
    async fn scan_does_not_alert_a_live_worker() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let handle = task.abort_handle();
        let workers = vec![WatchedWorker::new("live", handle.clone())];
        let mut alerted = vec![false; 1];
        scan_workers(&workers, &mut alerted, &writer).await;
        assert!(!alerted[0], "a live worker must NOT alert");
        handle.abort();
        drop(writer);
        let _ = join.await;
    }
}
