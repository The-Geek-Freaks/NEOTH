//! GOLD-ADAPT-GRAPH-05 — NEOTH self-map cron.
//!
//! When `freedom.yaml::obsidian_vault` AND a source directory (either
//! `freedom.yaml::self_map_source_dir` or env `NEOTH_SRC_DIR`) are configured,
//! this task runs `python -I -m graphify update` on the daemon source tree on a
//! schedule and:
//!
//!   1. Runs `python -I -m graphify update <source_dir>` — produces
//!      `graphify-out/GRAPH_REPORT.md` + `graphify-out/GRAPH_TREE.html` under
//!      the source dir.
//!   2. Rebuilds and atomically persists the native symbol map + call graph
//!      from verified source bytes.
//!   3. Publishes a validated immutable Graphify generation below
//!      `<vault>/<subdir>/generations/` (default `NEOTH-Self/`) and advances
//!      `CURRENT` atomically, making the structural graph browsable in Obsidian.
//!   4. Ingests the report text into `idx_groundtruth` (scope
//!      `neoth-self-map`) so `recall("what are NEOTH's core abstractions")`
//!      returns graph-derived answers.
//!   5. Emits a generation-bound `0xFB SELF_MAP_COMPLETE` WAL frame so
//!      operators can track cron health via `neoth wal show`.
//!
//! Off by default — requires `obsidian_vault` AND a reachable source dir.
//! Errors log + continue on next tick; never crash the daemon.
//!
//! GRAPH-07 optionally runs `graphify label` through the configured provider
//! before the immutable generation is captured.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::wal::HeaderBuilder;
use crate::wal::events::EVENT_TYPE_SELF_MAP_COMPLETE;
use crate::wal::writer::WalWriterHandle;

/// Default rebuild cadence: every 24 hours. The source tree changes often
/// enough that a daily graph refresh is meaningful without burning I/O.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default vault subdir for self-map output.
pub const DEFAULT_SUBDIR: &str = "NEOTH-Self";
const GRAPH_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const GRAPH_PROBE_OUTPUT_CAP: usize = 64 * 1024;
const GRAPH_UPDATE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const GRAPH_UPDATE_STDOUT_CAP: usize = 2 * 1024 * 1024;
const GRAPH_UPDATE_STDERR_CAP: usize = 512 * 1024;
const GRAPH_LABEL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const GRAPH_LABEL_STDOUT_CAP: usize = 2 * 1024 * 1024;
const GRAPH_LABEL_STDERR_CAP: usize = 512 * 1024;

/// Observable lifecycle phase for the cooperative SelfMap owner.  This is
/// deliberately coarse: it answers the shutdown question that matters (is a
/// side-effecting phase still being awaited?) without claiming an operation is
/// cancellable when its underlying blocking work is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfMapPhase {
    Idle,
    Preflight,
    Graphify,
    NativeSnapshot,
    Publish,
    Sqlite,
    CompletionWal,
    FinishJournal,
    Stopped,
}

/// The only owner of a running SelfMap cron.
///
/// Unlike ordinary cron handles, this is never aborted: Tokio aborting the
/// outer future would detach an already-started `spawn_blocking` closure.  The
/// watch bit is checked at every effect boundary and the join remains owned
/// until the task has really reached a terminal state.
pub struct SelfMapTaskHandle {
    cancel: watch::Sender<bool>,
    join: Option<JoinHandle<anyhow::Result<()>>>,
    phase: Arc<Mutex<SelfMapPhase>>,
}

impl SelfMapTaskHandle {
    pub fn request_stop(&self) {
        let _ = self.cancel.send(true);
    }

    pub fn is_finished(&self) -> bool {
        self.join.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub fn phase(&self) -> SelfMapPhase {
        *self.phase.lock().expect("self-map phase mutex poisoned")
    }

    /// Await a real terminal state without ever detaching the owned task.  A
    /// timeout deliberately leaves `join` in place so the fleet can retain it
    /// and suppress a successor on the next reconciliation pass.
    pub async fn wait_stopped(&mut self, timeout: Duration) -> anyhow::Result<bool> {
        self.request_stop();
        let result = {
            let Some(join) = self.join.as_mut() else {
                return Ok(true);
            };
            tokio::time::timeout(timeout, join).await
        };
        match result {
            Ok(Ok(Ok(()))) => {
                self.join.take();
                self.set_phase(SelfMapPhase::Stopped);
                Ok(true)
            }
            Ok(Ok(Err(error))) => {
                self.join.take();
                self.set_phase(SelfMapPhase::Stopped);
                Err(error.context("self-map task stopped with an error"))
            }
            Ok(Err(error)) => {
                self.join.take();
                self.set_phase(SelfMapPhase::Stopped);
                Err(anyhow::anyhow!(
                    "self-map task panicked while stopping: {error}"
                ))
            }
            Err(_) => Ok(false),
        }
    }

    fn set_phase(&self, phase: SelfMapPhase) {
        *self.phase.lock().expect("self-map phase mutex poisoned") = phase;
    }

    #[cfg(test)]
    pub(crate) fn from_test_task(join: JoinHandle<anyhow::Result<()>>) -> Self {
        let (cancel, _cancel_rx) = watch::channel(false);
        Self {
            cancel,
            join: Some(join),
            phase: Arc::new(Mutex::new(SelfMapPhase::Preflight)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("self-map cancellation requested")]
struct SelfMapCancelled;

fn set_phase(phase: &Arc<Mutex<SelfMapPhase>>, value: SelfMapPhase) {
    *phase.lock().expect("self-map phase mutex poisoned") = value;
}

fn stop_if_cancelled(cancel: &watch::Receiver<bool>) -> anyhow::Result<()> {
    if *cancel.borrow() {
        return Err(SelfMapCancelled.into());
    }
    Ok(())
}

/// Spawn the self-map cron task with an owning, cooperative cancellation
/// handle.  The caller must retain the handle until `wait_stopped` reports a
/// terminal state; aborting the outer task would detach blocking work.
///
/// * `vault` — vault root directory (from `freedom.yaml::obsidian_vault`).
/// * `source_dir` — the NEOTH daemon source tree to graph
///   (from `freedom.yaml::self_map_source_dir` or env `NEOTH_SRC_DIR`).
/// * `subdir` — vault subdir; `None` → [`DEFAULT_SUBDIR`].
/// * `interval` — tick cadence; `None` → [`DEFAULT_INTERVAL`].
/// * `writer` — WAL writer handle; the task emits `0xFB SELF_MAP_COMPLETE`.
/// * `label_enabled` — GRAPH-07: run `graphify label` after `update` to name communities.
/// * `label_model` — GRAPH-07: optional model override for `graphify label`.
/// * `label_provider` — caller-owned authorized provider boundary. Graphify
///   only receives a short-lived loopback broker capability, never a key,
///   provider kind, upstream endpoint, or Claude CLI authority.
///
/// Must be cooperatively drained BEFORE `drop(writer)` in
/// `shutdown_background_tasks`.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: Option<String>,
    interval: Option<Duration>,
    writer: WalWriterHandle,
    label_enabled: bool,
    label_model: Option<String>,
    label_provider: Option<Arc<crate::providers::cost_authorization::AuthorizedProvider>>,
    views_db: PathBuf,
) -> SelfMapTaskHandle {
    let subdir = subdir.unwrap_or_else(|| DEFAULT_SUBDIR.to_string());
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let (cancel, cancel_rx) = watch::channel(false);
    let phase = Arc::new(Mutex::new(SelfMapPhase::Idle));
    let task_phase = Arc::clone(&phase);
    let join = tokio::spawn(async move {
        run(
            vault,
            source_dir,
            subdir,
            interval,
            writer,
            label_enabled,
            label_model,
            label_provider,
            views_db,
            cancel_rx,
            task_phase,
        )
        .await
    });
    SelfMapTaskHandle {
        cancel,
        join: Some(join),
        phase,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: String,
    interval: Duration,
    writer: WalWriterHandle,
    label_enabled: bool,
    label_model: Option<String>,
    label_provider: Option<Arc<crate::providers::cost_authorization::AuthorizedProvider>>,
    views_db: PathBuf,
    mut cancel: watch::Receiver<bool>,
    phase: Arc<Mutex<SelfMapPhase>>,
) -> anyhow::Result<()> {
    info!(
        vault = %vault.display(),
        source_dir = %source_dir.display(),
        subdir = %subdir,
        interval_secs = interval.as_secs(),
        label_enabled,
        "GOLD-ADAPT-GRAPH-05: self-map cron started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — burn-first-tick pattern identical to
    // `obsidian_wiki_rebuild_task`: at boot the daemon is still initialising
    // and the source tree may not be fully visible yet.
    tokio::select! {
        _ = ticker.tick() => {}
        changed = cancel.changed() => {
            let _ = changed;
            set_phase(&phase, SelfMapPhase::Stopped);
            return Ok(());
        }
    }
    loop {
        set_phase(&phase, SelfMapPhase::Idle);
        tokio::select! {
            _ = ticker.tick() => {}
            changed = cancel.changed() => {
                let _ = changed;
                set_phase(&phase, SelfMapPhase::Stopped);
                return Ok(());
            }
        }
        if stop_if_cancelled(&cancel).is_err() {
            set_phase(&phase, SelfMapPhase::Stopped);
            return Ok(());
        }
        if let Err(e) = run_one_tick(
            &vault,
            &source_dir,
            &subdir,
            &writer,
            label_enabled,
            &label_model,
            &label_provider,
            &views_db,
            &cancel,
            &phase,
        )
        .await
        {
            if e.downcast_ref::<SelfMapCancelled>().is_some() {
                info!("self-map cron stopped cooperatively between effect phases");
                set_phase(&phase, SelfMapPhase::Stopped);
                return Ok(());
            }
            warn!(
                error = %e,
                "self-map cron tick failed (will retry next interval)"
            );
        }
    }
}

/// Probe Graphify availability through the bounded child runner. Returns
/// `Ok(())` only when `python -I -m graphify --version` exits successfully within
/// the configured deadline and output limits.
///
/// Exported `pub` so `cli::graph` (GOLD-ADAPT-GRAPH-06 one-shot CLI) can reuse
/// the probe without duplicating it.
pub async fn check_graphify_available(
    runtime: &crate::graphify_runner::GraphifyRuntime,
) -> anyhow::Result<()> {
    let limits = crate::graphify_runner::GraphifyRunLimits::new(
        "graph-probe",
        GRAPH_PROBE_TIMEOUT,
        GRAPH_PROBE_OUTPUT_CAP,
        GRAPH_PROBE_OUTPUT_CAP,
    )?;
    crate::graphify_runner::run_graphify_process(
        crate::graphify_runner::GraphifyRunRequest::with_runtime(runtime.clone(), limits).args([
            "-I",
            "-m",
            "graphify",
            "--version",
        ]),
    )
    .await
    .context(
        "self-map: bounded Graphify probe failed; configured Graphify runtime is unavailable",
    )?;
    Ok(())
}

/// One self-map tick: probe → update → [label] → copy → ingest → WAL frame.
#[allow(clippy::too_many_arguments)]
async fn run_one_tick(
    vault: &Path,
    source_dir: &Path,
    subdir: &str,
    writer: &WalWriterHandle,
    label_enabled: bool,
    label_model: &Option<String>,
    label_provider: &Option<Arc<crate::providers::cost_authorization::AuthorizedProvider>>,
    views_db: &Path,
    cancel: &watch::Receiver<bool>,
    phase: &Arc<Mutex<SelfMapPhase>>,
) -> anyhow::Result<()> {
    set_phase(phase, SelfMapPhase::Preflight);
    stop_if_cancelled(cancel)?;
    // Resolve one canonical physical root up front. The same identity is used
    // by Graphify and the native generation receipt.
    let source_root = crate::code_map::CanonicalRepoRoot::discover(source_dir)
        .context("self-map: resolve canonical source root")?;
    let source_dir = source_root.path().to_path_buf();
    stop_if_cancelled(cancel)?;

    // Resolve once before any Graphify child receives the corpus cwd. The same
    // opaque token is reused for probe, update, and optional label execution.
    let runtime = crate::graphify_runner::GraphifyRuntime::discover("python")
        .await
        .context("self-map: resolve verified Graphify runtime")?;
    stop_if_cancelled(cancel)?;

    // A missing Graphify runtime is a failed tick, not a successful no-op. The
    // cron supervisor records the partial attempt and retries next interval.
    check_graphify_available(&runtime)
        .await
        .context("self-map: graphify probe failed")?;
    stop_if_cancelled(cancel)?;

    let native_db = instance_code_map_path(views_db)?;
    let fingerprint_root = source_root.clone();
    set_phase(phase, SelfMapPhase::NativeSnapshot);
    let pre_graphify_fingerprint = tokio::task::spawn_blocking(move || {
        crate::code_map::snapshot::stable_source_fingerprint(
            &fingerprint_root,
            crate::code_map::RebuildOptions::default(),
        )
    })
    .await
    .context("self-map: pre-Graphify source fingerprint task panicked")?
    .context("self-map: pre-Graphify source fingerprint failed")?;
    stop_if_cancelled(cancel)?;

    // Take the lease before Graphify can mutate graphify-out. Recovery keeps
    // that same lease through its SQLite and terminal WAL boundaries; only a
    // no-pending result hands it to the new publication below.
    let recovery_vault = vault.to_path_buf();
    let recovery_root = source_root.clone();
    let recovery_native_db = native_db.clone();
    let recovery_views = views_db.to_path_buf();
    set_phase(phase, SelfMapPhase::Preflight);
    let recovery_open = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let lease = crate::graphify_publish::acquire_graphify_publication_lease(
            &recovery_vault,
            &recovery_root,
        )?;
        let targets = crate::graphify_transaction::discover_graphify_recovery_targets(&lease)?;
        anyhow::ensure!(
            targets.len() <= 1,
            "self-map: multiple pending Graphify publication journals share one corpus identity"
        );
        let Some(corpus_dir) = targets.into_iter().next() else {
            return Ok((
                crate::graphify_transaction::GraphifyRecoveryOpen::NoPendingPublication(Box::new(
                    lease,
                )),
                None,
            ));
        };
        crate::graphify_transaction::preflight_graphify_recovery_scope_under_lease(
            &lease,
            &corpus_dir,
            crate::wiki::GraphifyIngestScope::SelfMap,
        )?;
        let (_, receipt) =
            crate::graphify_publish::load_current_graphify_generation_receipt(&corpus_dir)?
                .context("self-map: recovery journal has no CURRENT receipt")?;
        let attestation = crate::code_map::snapshot::attest_existing_persisted_snapshot(
            &recovery_root,
            &recovery_native_db,
            crate::code_map::RebuildOptions::default(),
            &receipt.source_fingerprint_sha256,
            receipt.native_index_generation,
            receipt.native_graph_generation,
        )?;
        let conn = crate::memory::store::open(&recovery_views)
            .context("self-map: open views.db for Graphify recovery")?;
        let recovery = crate::graphify_transaction::open_graphify_transaction_recovery(
            &conn,
            lease,
            &attestation,
            &corpus_dir,
            crate::wiki::GraphifyIngestScope::SelfMap,
        )?;
        Ok((recovery, Some(attestation)))
    })
    .await
    .context("self-map: Graphify lease/recovery task panicked")??;
    let (recovery_open, recovery_attestation) = recovery_open;
    stop_if_cancelled(cancel)?;
    let publication_lease = match recovery_open {
        crate::graphify_transaction::GraphifyRecoveryOpen::NoPendingPublication(lease) => *lease,
        crate::graphify_transaction::GraphifyRecoveryOpen::Pending(recovery) => {
            let apply_snapshot =
                recovery_attestation.context("self-map: missing native recovery attestation")?;
            let completion_snapshot = apply_snapshot.clone();
            let apply_views = views_db.to_path_buf();
            set_phase(phase, SelfMapPhase::Sqlite);
            let recovery_wal = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let conn = crate::memory::store::open(&apply_views)
                    .context("self-map: open views.db for recovered Graphify transaction")?;
                recovery.apply_sqlite_phase(&conn, &apply_snapshot, crate::time::now_unix_ns_i64())
            })
            .await
            .context("self-map: recovered Graphify SQLite task panicked")??;
            stop_if_cancelled(cancel)?;
            let transaction_id = recovery_wal.transaction_id().as_str().to_owned();
            let receipt = recovery_wal.receipt().clone();
            let recovery_mode = match recovery_wal.ingest_mode() {
                crate::graphify_transaction::GraphifyIngestMode::Indexed => "recovered_indexed",
                crate::graphify_transaction::GraphifyIngestMode::SkippedAndRevoked => {
                    "published_unindexed"
                }
            };
            let body = self_map_completion_payload(SelfMapCompletionEvidence {
                pages_written: u64::try_from(receipt.artifacts.len())?,
                gt_inserted: 0,
                label_status: "recovered",
                communities_labeled: None,
                transaction_id: &transaction_id,
                publication_status: recovery_mode,
                native_snapshot: &completion_snapshot,
                graphify_receipt: &receipt,
                now_ns: crate::time::now_unix_ns_i64(),
            })?;
            let header = HeaderBuilder::new(EVENT_TYPE_SELF_MAP_COMPLETE, &body).build();
            set_phase(phase, SelfMapPhase::CompletionWal);
            writer
                .append(header, body)
                .await
                .context("self-map: append recovered completion WAL")?;
            // Once the completion frame is durable, the journal must be
            // terminalized even if shutdown raced this boundary.
            set_phase(phase, SelfMapPhase::FinishJournal);
            tokio::task::spawn_blocking(move || recovery_wal.finish_after_durable_wal())
                .await
                .context("self-map: recovered Graphify finish task panicked")?
                .context("self-map: finish recovered Graphify transaction")?;
            info!(%transaction_id, "self-map recovered pending Graphify transaction");
            return Ok(());
        }
    };

    // Step 1: run `python -I -m graphify update <source_dir>`.
    // graphify writes output to `graphify-out/` RELATIVE TO ITS CWD, so we
    // set cwd = source_dir (pitfall #2).
    let update_limits = crate::graphify_runner::GraphifyRunLimits::new(
        "graph-update",
        GRAPH_UPDATE_TIMEOUT,
        GRAPH_UPDATE_STDOUT_CAP,
        GRAPH_UPDATE_STDERR_CAP,
    )?;
    set_phase(phase, SelfMapPhase::Graphify);
    crate::graphify_runner::run_graphify_process(
        crate::graphify_runner::GraphifyRunRequest::with_runtime(runtime.clone(), update_limits)
            .args(["-I", "-m", "graphify", "update", "."])
            .current_dir(&source_dir),
    )
    .await
    .context("self-map: bounded `python -I -m graphify update` failed")?;
    stop_if_cancelled(cancel)?;

    // GRAPH-07: label communities via the configured provider (operator opt-in).
    // Runs BEFORE Step 2 (locate output files) so the labeled GRAPH_REPORT.md
    // is the one copied to the vault and ingested — not the unlabeled version.
    let label_outcome = if label_enabled {
        set_phase(phase, SelfMapPhase::Graphify);
        run_label_step(
            &source_dir,
            runtime.clone(),
            label_provider
                .as_ref()
                .context("GRAPH-07: label is enabled but no authorized provider was wired")?
                .clone(),
            label_model,
        )
        .await
        .context("self-map: enabled Graphify label step failed")?
    } else {
        LabelOutcome::disabled()
    };
    stop_if_cancelled(cancel)?;

    // GOLD-R3-13: publish the native symbol map + call graph before any vault
    // copy, ingest, or completion WAL. A failed rebuild propagates out of the
    // tick, so no downstream surface can claim completion for a partial map.
    set_phase(phase, SelfMapPhase::NativeSnapshot);
    let native_snapshot = tokio::task::spawn_blocking(move || {
        crate::code_map::snapshot::rebuild_snapshot_scoped(
            &source_root,
            &native_db,
            crate::code_map::RebuildOptions::default(),
            &[],
            &[],
        )
    })
    .await
    .context("self-map: native code-map rebuild task panicked")?
    .context("self-map: native code-map rebuild failed")?;
    anyhow::ensure!(
        native_snapshot.snapshot().source_fingerprint_sha256 == pre_graphify_fingerprint,
        "self-map: source corpus changed while Graphify was running; refusing mixed Graphify/native completion"
    );
    stop_if_cancelled(cancel)?;

    // Step 2/3: validate and atomically publish one immutable vault generation.
    // Unsafe names, source links/reparse points, oversized artifacts and root
    // replacement all fail before CURRENT can advance.
    let publish_vault = vault.to_path_buf();
    let publish_subdir = subdir.to_owned();
    let publish_snapshot = native_snapshot.clone();
    set_phase(phase, SelfMapPhase::Publish);
    let published = tokio::task::spawn_blocking(move || {
        crate::graphify_publish::prepare_graphify_publication(
            crate::graphify_publish::GraphifyPublishRequest {
                vault_root: &publish_vault,
                friendly_subdir: Some(&publish_subdir),
                native_snapshot: &publish_snapshot,
                ingest_mode: crate::graphify_publish::GraphifyPublicationIngestMode::Indexed,
                ingest_scope: crate::wiki::GraphifyIngestScope::SelfMap,
                lease: publication_lease,
            },
        )?
        .publish()
    })
    .await
    .context("self-map: Graphify publication task panicked")?
    .context("self-map: validate and publish Graphify vault generation")?;
    let pages_written = u64::try_from(published.receipt.artifacts.len())
        .context("self-map: artifact count does not fit u64")?;
    stop_if_cancelled(cancel)?;

    // Step 4: use the coordinator for SQLite and its matching journal phase.
    // It keeps the pre-update lease through the terminal caller WAL.
    let views_db = views_db.to_path_buf();
    let sqlite_snapshot = native_snapshot.clone();
    set_phase(phase, SelfMapPhase::Sqlite);
    let pending = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let conn = crate::memory::store::open(&views_db).context("self-map: open views.db")?;
        crate::graphify_transaction::apply_graphify_sqlite_phase(
            published,
            &conn,
            &sqlite_snapshot,
            crate::wiki::GraphifyIngestScope::SelfMap,
            crate::graphify_transaction::GraphifyIngestMode::Indexed,
            crate::time::now_unix_ns_i64(),
        )
    })
    .await
    .context("self-map: Graphify SQLite transaction task panicked")??;
    let transaction_id = pending.transaction_id().as_str().to_owned();
    let receipt = pending.receipt().clone();
    let gt_inserted = match pending.outcome() {
        crate::graphify_transaction::GraphifyTransactionOutcome::Indexed { stats, .. } => {
            u64::try_from(stats.inserted).context("self-map: inserted count does not fit u64")?
        }
        crate::graphify_transaction::GraphifyTransactionOutcome::SkippedAndRevoked { .. } => 0,
    };
    stop_if_cancelled(cancel)?;

    // Step 5: emit 0xFB SELF_MAP_COMPLETE WAL frame.
    let body = self_map_completion_payload(SelfMapCompletionEvidence {
        pages_written,
        gt_inserted,
        label_status: label_outcome.status.as_str(),
        communities_labeled: label_outcome.communities_labeled,
        transaction_id: &transaction_id,
        publication_status: "complete",
        native_snapshot: &native_snapshot,
        graphify_receipt: &receipt,
        now_ns: crate::time::now_unix_ns_i64(),
    })?;
    let header = HeaderBuilder::new(EVENT_TYPE_SELF_MAP_COMPLETE, &body).build();
    set_phase(phase, SelfMapPhase::CompletionWal);
    writer
        .append(header, body)
        .await
        .context("self-map: append completion WAL")?;
    // Do not observe cancellation between the terminal completion frame and
    // journal finalization: both belong to one durable transaction.
    set_phase(phase, SelfMapPhase::FinishJournal);
    let _transaction_outcome =
        tokio::task::spawn_blocking(move || pending.finish_after_durable_wal())
            .await
            .context("self-map: Graphify transaction finish task panicked")?
            .context("self-map: finish Graphify transaction after completion WAL")?;

    info!(
        pages_written,
        gt_inserted,
        label_status = label_outcome.status.as_str(),
        communities_labeled = ?label_outcome.communities_labeled,
        index_generation = native_snapshot.snapshot().index_generation,
        graph_generation = native_snapshot.snapshot().graph_generation,
        graphify_generation = %receipt.generation_id,
        "self-map cron tick complete (GOLD-ADAPT-GRAPH-05/07/R3-13)",
    );
    Ok(())
}

fn instance_code_map_path(views_db: &Path) -> anyhow::Result<PathBuf> {
    let home = views_db
        .parent()
        .context("self-map: instance views.db has no parent home")?;
    Ok(home.join("code_map.db"))
}

/// Complete, generation-bound evidence for one `SELF_MAP_COMPLETE` WAL frame.
/// Keeping the fields together prevents completion payload call sites from
/// accidentally binding metrics to a different transaction, receipt, or native
/// snapshot.
struct SelfMapCompletionEvidence<'a, S: crate::code_map::snapshot::CompanionSnapshotAttestation> {
    pages_written: u64,
    gt_inserted: u64,
    label_status: &'a str,
    communities_labeled: Option<u64>,
    transaction_id: &'a str,
    publication_status: &'a str,
    native_snapshot: &'a S,
    graphify_receipt: &'a crate::graphify_publish::GraphifyGenerationReceipt,
    now_ns: i64,
}

fn self_map_completion_payload<S: crate::code_map::snapshot::CompanionSnapshotAttestation>(
    evidence: SelfMapCompletionEvidence<'_, S>,
) -> anyhow::Result<Vec<u8>> {
    let SelfMapCompletionEvidence {
        pages_written,
        gt_inserted,
        label_status,
        communities_labeled,
        transaction_id,
        publication_status,
        native_snapshot,
        graphify_receipt,
        now_ns,
    } = evidence;
    serde_json::to_vec(&serde_json::json!({
        "pages_written":        pages_written,
        "gt_inserted":          gt_inserted,
        "label_status":         label_status,
         "communities_labeled":  communities_labeled,
         "graphify_transaction_id": transaction_id,
         "publication_status": publication_status,
         "root_identity_sha256": native_snapshot.root_identity_sha256(),
         "source_fingerprint_sha256": native_snapshot.source_fingerprint_sha256(),
        "index_generation":     native_snapshot.index_generation(),
        "graph_generation":     native_snapshot.graph_generation(),
        "graphify_generation": {
            "schema_version": graphify_receipt.schema_version,
            "corpus_id": graphify_receipt.corpus_id,
            "corpus_namespace": graphify_receipt.corpus_namespace,
            "generation_id": graphify_receipt.generation_id,
            "source_fingerprint_sha256": graphify_receipt.source_fingerprint_sha256,
            "native_index_generation": graphify_receipt.native_index_generation,
            "native_graph_generation": graphify_receipt.native_graph_generation,
            "artifacts": graphify_receipt.artifacts,
        },
        "ts_unix":              now_ns / 1_000_000_000,
    }))
    .context("self-map: serialize completion payload")
}

/// GRAPH-07 CLI entry point. Build the provider from the selected instance,
/// constrain it through an interactive one-shot authorizer, and wait for that
/// author's WAL lifecycle only after the broker has drained every request.
pub(crate) async fn run_label_step_one_shot(
    source_dir: &Path,
    runtime: crate::graphify_runner::GraphifyRuntime,
    config: &crate::config::FreedomConfig,
    home: &Path,
    label_model: &Option<String>,
) -> anyhow::Result<LabelOutcome> {
    let raw = crate::providers::from_config_at(config, home)
        .await
        .context("GRAPH-07: construct CLI label provider from selected home")?;
    let wire_model = label_model
        .as_deref()
        .map(|model| raw.resolve_model_for_wire(model))
        .or_else(|| crate::providers::provider_default_wire_model(raw.as_ref()))
        .filter(|model| !model.trim().is_empty())
        .context("GRAPH-07: configured label provider has no final wire model")?;
    let one_shot =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot_at_home(
            config.autonomy_policy(),
            home,
            config.tokens.max_per_request,
        )
        .await
        .context("GRAPH-07: initialize CLI provider authorization WAL")?;
    let provider = Arc::new(
        crate::providers::cost_authorization::AuthorizedProvider::from_box(
            raw,
            one_shot.authorizer(),
            Some(wire_model.clone()),
            "graphify.label.cli",
        ),
    );
    let label_result = run_label_step(
        source_dir,
        runtime,
        Arc::clone(&provider),
        &Some(wire_model),
    )
    .await;
    let finish_result = one_shot.finish(provider).await;
    match (label_result, finish_result) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(label_error), Ok(())) => Err(label_error),
        (Ok(_), Err(finish_error)) => {
            Err(finish_error).context("GRAPH-07: finalize CLI provider authorization WAL")
        }
        (Err(label_error), Err(finish_error)) => Err(anyhow::anyhow!(
            "GRAPH-07: label failed ({label_error:#}) and provider authorization WAL finalization failed ({finish_error:#})"
        )),
    }
}

async fn run_label_step(
    source_dir: &Path,
    runtime: crate::graphify_runner::GraphifyRuntime,
    provider: Arc<crate::providers::cost_authorization::AuthorizedProvider>,
    label_model: &Option<String>,
) -> anyhow::Result<LabelOutcome> {
    let model = label_model
        .as_deref()
        .filter(|model| !model.trim().is_empty())
        .context("GRAPH-07: label broker requires the exact final wire model")?;
    let broker = crate::graphify_label_broker::GraphifyLabelBroker::bind(
        provider,
        model,
        // Graphify 0.8.41's private cluster plan is not reconstructed here.
        // Keep this temporary admission explicitly conservative rather than
        // presenting it as an exact planned-batch capability.
        crate::graphify_label_broker::GraphifyLabelBrokerConfig::for_budgeted_batches(16, 1600)
            .context("GRAPH-07: configure conservative budgeted label broker")?,
    )
    .await
    .context("GRAPH-07: start loopback label broker")?;
    let connection = broker.connection().clone();
    info!(
        authorization_mode = ?connection.authorization_mode,
        "GRAPH-07 using conservative budgeted label broker authorization"
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let broker_task = tokio::spawn(async move {
        broker
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let backend_flag = format!("--backend={}", connection.backend);
    let model_flag = format!("--model={}", connection.model);
    let environment = crate::graphify_runner::GraphifyEnvironment::label_broker(
        &connection.ollama_base_url,
        &connection.model,
    )
    .context("GRAPH-07: construct credentialless label-child environment")?;
    let limits = crate::graphify_runner::GraphifyRunLimits::new(
        "graph-label",
        GRAPH_LABEL_TIMEOUT,
        GRAPH_LABEL_STDOUT_CAP,
        GRAPH_LABEL_STDERR_CAP,
    )
    .context("GRAPH-07: invalid bounded label-runner configuration")?;

    let result = crate::graphify_runner::run_graphify_process(
        crate::graphify_runner::GraphifyRunRequest::with_runtime(runtime, limits)
            .args([
                "-I",
                "-m",
                "graphify",
                "label",
                ".",
                &backend_flag,
                &model_flag,
            ])
            .current_dir(source_dir)
            .environment(environment),
    )
    .await
    .context("GRAPH-07: bounded graphify label failed");
    let _ = shutdown_tx.send(());
    let broker_result = broker_task
        .await
        .context("GRAPH-07: label broker task panicked")?
        .context("GRAPH-07: label broker drain failed");
    let out = match (result, broker_result) {
        (Ok(out), Ok(())) => out,
        (Err(label_error), Ok(())) => return Err(label_error),
        (Ok(_), Err(broker_error)) => return Err(broker_error),
        (Err(label_error), Err(broker_error)) => {
            return Err(anyhow::anyhow!(
                "GRAPH-07: graphify label failed ({label_error:#}) and broker drain failed ({broker_error:#})"
            ));
        }
    };
    info!(
        source_dir = %source_dir.display(),
        "GRAPH-07: graphify label completed through authorized loopback broker"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let communities_labeled = stdout
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|window| {
            window[1].trim_end_matches(|c: char| !c.is_ascii_alphabetic()) == "communities"
        })
        .and_then(|window| {
            window[0]
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        });
    Ok(LabelOutcome::complete(communities_labeled))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LabelOutcome {
    pub(crate) status: LabelStatus,
    pub(crate) communities_labeled: Option<u64>,
}

impl LabelOutcome {
    pub(crate) fn disabled() -> Self {
        Self {
            status: LabelStatus::Disabled,
            communities_labeled: None,
        }
    }

    fn complete(communities_labeled: Option<u64>) -> Self {
        Self {
            status: LabelStatus::Complete,
            communities_labeled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LabelStatus {
    Disabled,
    Complete,
}

impl LabelStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Complete => "complete",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn task_stops_cooperatively_while_idle() {
        // No real vault/source setup — the task should burn the first tick
        // and block on the second.  Stopping must be cooperative: no outer
        // `abort` is allowed because that can detach a blocking child later.
        let vault_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let views_db = home_dir.path().join("views.db");
        assert_ne!(
            views_db,
            crate::config::FreedomConfig::default_neoth_home().join("views.db"),
            "test must not target the process-default NEOTH home"
        );
        let (writer, _writer_join) =
            crate::wal::writer::spawn(wal_dir.path().join("neoth.wal")).unwrap();

        let mut task = spawn(
            vault_dir.path().to_path_buf(),
            source_dir.path().to_path_buf(),
            Some(DEFAULT_SUBDIR.into()),
            Some(Duration::from_millis(50)),
            writer,
            false, // label_enabled — off for idle stop test
            None,  // label_model
            None,  // label_provider
            views_db,
        );
        // Let the task burn the first tick and enter the loop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.request_stop();
        assert!(
            task.wait_stopped(Duration::from_secs(2)).await.unwrap(),
            "idle SelfMap task must observe cancellation and join"
        );
        assert_eq!(task.phase(), SelfMapPhase::Stopped);
    }

    #[tokio::test]
    async fn blocking_phase_timeout_retains_owner_until_work_finishes() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.blocking_recv();
            })
            .await
            .context("test blocking phase panicked")?;
            Ok(())
        });
        let mut task = SelfMapTaskHandle::from_test_task(join);
        entered_rx.await.expect("blocking phase did not start");
        assert!(
            !task.wait_stopped(Duration::from_millis(10)).await.unwrap(),
            "timeout must retain the live owner rather than detaching it"
        );
        assert!(
            !task.is_finished(),
            "live blocking closure must remain owned"
        );
        release_tx.send(()).expect("release receiver disappeared");
        assert!(
            task.wait_stopped(Duration::from_secs(2)).await.unwrap(),
            "released blocking phase must be reaped by the same owner"
        );
    }

    #[test]
    fn native_code_map_is_scoped_to_selected_instance_home() {
        let home = tempfile::tempdir().unwrap();
        let views_db = home.path().join("views.db");
        assert_eq!(
            instance_code_map_path(&views_db).unwrap(),
            home.path().join("code_map.db")
        );
        assert_ne!(
            instance_code_map_path(&views_db).unwrap(),
            crate::code_map::persist::default_path()
        );
    }

    #[test]
    fn completion_payload_binds_digest_and_matching_native_generations() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("lib.rs"), "pub fn mapped() {}\n").unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let snapshot = crate::code_map::snapshot::rebuild_snapshot_scoped(
            &root,
            &db_dir.path().join("code_map.db"),
            crate::code_map::RebuildOptions::default(),
            &[],
            &[],
        )
        .unwrap();

        let graphify_receipt = crate::graphify_publish::GraphifyGenerationReceipt {
            schema_version: 1,
            corpus_id: "corpus-id".to_owned(),
            corpus_namespace: "corpus-namespace".to_owned(),
            generation_id: "generation-id".to_owned(),
            friendly_subdir: "NEOTH-Self".to_owned(),
            canonical_repo_root: snapshot.snapshot().root.display().to_owned(),
            repo_root_identity_sha256: snapshot.snapshot().root_identity_sha256.clone(),
            canonical_vault_root: "C:/private/vault".to_owned(),
            vault_root_identity_sha256: "v".repeat(64),
            source_fingerprint_sha256: snapshot.snapshot().source_fingerprint_sha256.clone(),
            native_index_generation: snapshot.snapshot().index_generation,
            native_graph_generation: snapshot.snapshot().graph_generation,
            artifacts: vec![crate::graphify_publish::GraphifyArtifactReceipt {
                name: "GRAPH_REPORT.md".to_owned(),
                bytes: 42,
                sha256: "a".repeat(64),
            }],
        };
        let body = self_map_completion_payload(SelfMapCompletionEvidence {
            pages_written: 2,
            gt_inserted: 3,
            label_status: "complete",
            communities_labeled: Some(4),
            transaction_id: "transaction-id",
            publication_status: "complete",
            native_snapshot: &snapshot,
            graphify_receipt: &graphify_receipt,
            now_ns: 5_000_000_000,
        })
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            payload["root_identity_sha256"],
            snapshot.snapshot().root_identity_sha256
        );
        assert_eq!(
            payload["source_fingerprint_sha256"],
            snapshot.snapshot().source_fingerprint_sha256
        );
        assert_eq!(
            payload["index_generation"],
            snapshot.snapshot().index_generation
        );
        assert_eq!(
            payload["graph_generation"],
            snapshot.snapshot().graph_generation
        );
        assert_eq!(payload["index_generation"], payload["graph_generation"]);
        assert_eq!(payload["label_status"], "complete");
        assert_eq!(payload["communities_labeled"], 4);
        assert_eq!(
            payload["graphify_generation"]["generation_id"],
            graphify_receipt.generation_id
        );
        assert_eq!(
            payload["graphify_generation"]["source_fingerprint_sha256"],
            snapshot.snapshot().source_fingerprint_sha256
        );
        assert_eq!(payload["ts_unix"], 5);
        assert!(
            !String::from_utf8(body)
                .unwrap()
                .contains(snapshot.snapshot().root.display()),
            "completion audit must not persist the raw repository path"
        );
        assert!(
            !String::from_utf8(
                self_map_completion_payload(SelfMapCompletionEvidence {
                    pages_written: 2,
                    gt_inserted: 3,
                    label_status: "complete",
                    communities_labeled: Some(4),
                    transaction_id: "transaction-id",
                    publication_status: "complete",
                    native_snapshot: &snapshot,
                    graphify_receipt: &graphify_receipt,
                    now_ns: 5_000_000_000,
                })
                .unwrap()
            )
            .unwrap()
            .contains("C:/private/vault"),
            "completion audit must not persist the raw vault path"
        );
    }
}
