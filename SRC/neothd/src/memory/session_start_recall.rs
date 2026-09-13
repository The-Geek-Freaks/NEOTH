//! Bounded session-start local recall preload.
//!
//! This is a standalone generic `views.db` reader: it does not require
//! transcript-mining opt-in, a WAL writer, or an HMAC key.  The reader borrows
//! the existing Stage-4 *detection*
//! contract (retained directory/file identity, no-follow read-only SQLite,
//! `query_only`, and before/after `data_version` checks).  Those checks detect
//! replacement and concurrent commits; they are not an immutable-VFS claim.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use cap_std::fs::Dir;
use rusqlite::{Connection, OpenFlags, limits::Limit};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

const PRELOAD_CAPACITY: usize = 2;
const RECALL_LANE_LIMIT: usize = 5;
const MAX_PROMPT_TOKENS: u32 = 4 * 1024;
const MAX_SESSION_BINDING_BYTES: usize = 512;
const MAX_SQLITE_VALUE_BYTES: i32 = 64 * 1024;
/// The final chat renderer owns the 16 KiB wire cap.  This source cap is
/// tighter because the project token upper bound counts UTF-8 bytes.
const MAX_PRELOADED_SOURCE_TOKENS: u32 = 8 * 1024;
const RECALL_DEADLINE: Duration = Duration::from_millis(250);
const INTERRUPT_GRACE: Duration = Duration::from_millis(25);

/// A successful all-lane query can distinguish a true empty recall from a
/// skipped/missing preload.  Babel must only treat `Empty` as a true miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecallPreloadEmpty {
    /// The supplied prompt exceeded the pre-copy routing cap.
    Skipped,
    /// The existing home or its existing `views.db` was absent.
    Missing,
    /// All three checked recall lanes completed and yielded no rows.
    Empty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecallPreloadStale {
    BindingMismatch,
    DataVersionChanged,
    IdentityChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecallPreloadFailure {
    Capacity,
    Open,
    ReadOnlyLimit,
    Query,
    Deadline,
    Cancelled,
    Join,
    AlreadyConsumed,
}

/// Only `Ready` carries recall data.  The caller must immediately hand that
/// output to its normal `render_preloaded_recall` helper and enforce the final
/// 16 KiB `RenderedUntrustedContext` wire cap before provider dispatch.
pub(crate) enum SessionStartRecallOutcome {
    Ready {
        output: crate::cli::recall::RecallOutput,
    },
    NoData(RecallPreloadEmpty),
    Stale(RecallPreloadStale),
    Failed(RecallPreloadFailure),
}

/// Non-serializable, non-debuggable session-bound preload.  It retains the
/// generic read session only until one matching consumption attempt completes.
pub(crate) struct SessionStartRecallPreload {
    home: PathBuf,
    prompt_fingerprint: Option<[u8; 32]>,
    binding_fingerprint: [u8; 32],
    state: PreloadState,
}

enum PreloadState {
    Immediate(SessionStartRecallOutcome),
    Running(RecallWorker),
    Consumed,
}

struct RecallWorker {
    control: Arc<WorkerControl>,
    task: JoinHandle<WorkerCompletion>,
    watchdog: JoinHandle<()>,
    deadline: tokio::time::Instant,
}

/// SQLite's interrupt handle is created only after the connection exists.
/// A timeout before that point leaves `cancelled` set; the worker observes it
/// immediately after opening and drops its reader without issuing a query.
struct WorkerControl {
    cancelled: AtomicBool,
    deadline: std::time::Instant,
    interrupt: Mutex<Option<rusqlite::InterruptHandle>>,
}

impl WorkerControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            deadline: std::time::Instant::now() + RECALL_DEADLINE,
            interrupt: Mutex::new(None),
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= self.deadline
    }

    fn install_interrupt(&self, handle: rusqlite::InterruptHandle) {
        let mut slot = self
            .interrupt
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.cancelled() {
            handle.interrupt();
        } else {
            *slot = Some(handle);
        }
    }

    fn cancel_and_interrupt(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(handle) = self
            .interrupt
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            handle.interrupt();
        }
    }
}

enum WorkerCompletion {
    Queried {
        reader: Box<ExistingViewsReader>,
        observed_data_version: i64,
        output: crate::cli::recall::RecallOutput,
    },
    NoData(RecallPreloadEmpty),
    Stale(RecallPreloadStale),
    Failed(RecallPreloadFailure),
}

/// Interrupt is not a persistent pre-cancel token. The VM callback also checks
/// a monotonic deadline, so SQL that starts after cancellation cannot escape
/// it, even while ordinary prompt assembly delays the async watchdog's poll.
fn install_query_cancellation(conn: &Connection, control: &Arc<WorkerControl>) {
    control.install_interrupt(conn.get_interrupt_handle());
    let control = Arc::clone(control);
    conn.progress_handler(1_000, Some(move || control.cancelled()));
}

fn retire_worker(worker: RecallWorker) {
    let RecallWorker {
        control,
        task,
        watchdog,
        ..
    } = worker;
    control.cancel_and_interrupt();
    watchdog.abort();
    // Dropping a Tokio blocking JoinHandle never stops a running closure.  The
    // closure still owns its permit and therefore remains globally bounded at
    // two until SQLite/open returns and the permit drops.
    drop(task);
}

fn permits() -> &'static Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS.get_or_init(|| Arc::new(Semaphore::new(PRELOAD_CAPACITY)))
}

/// Start the bounded local recall work while ordinary prompt assembly proceeds.
///
/// `subject` is the opaque capability minted at the local chat boundary.  The
/// session binding is caller-owned opaque data (the chat integration supplies a
/// length-delimited operator-id/session-id binding); this module retains only a
/// domain-separated SHA-256 fingerprint, never the supplied text.
pub(crate) fn start_session_recall_preload(
    subject: &crate::cli::chat::LocalChatCommunicationSubject,
    home: PathBuf,
    session_binding: &str,
    prompt: &str,
) -> SessionStartRecallPreload {
    let binding_fingerprint = match binding_fingerprint(subject, session_binding) {
        Ok(value) => value,
        Err(_) => {
            return immediate(
                home,
                None,
                [0; 32],
                SessionStartRecallOutcome::Failed(RecallPreloadFailure::Open),
            );
        }
    };
    if crate::tokens::budget::count_tokens_upper_bound(prompt) > MAX_PROMPT_TOKENS {
        return immediate(
            home,
            None,
            binding_fingerprint,
            SessionStartRecallOutcome::NoData(RecallPreloadEmpty::Skipped),
        );
    }
    let prompt_fingerprint = Some(fingerprint(b"NEOTH/session-start-recall/prompt/v1", prompt));
    if crate::memory::recall_gate::classify_recall_need(prompt)
        == crate::memory::recall_gate::RecallTier::Skip
    {
        return immediate(
            home,
            prompt_fingerprint,
            binding_fingerprint,
            SessionStartRecallOutcome::NoData(RecallPreloadEmpty::Skipped),
        );
    }

    let Ok(permit) = Arc::clone(permits()).try_acquire_owned() else {
        return immediate(
            home,
            prompt_fingerprint,
            binding_fingerprint,
            SessionStartRecallOutcome::Failed(RecallPreloadFailure::Capacity),
        );
    };
    let control = Arc::new(WorkerControl::new());
    let worker_home = home.clone();
    let worker_prompt = prompt.to_owned();
    let worker_control = Arc::clone(&control);
    let deadline = tokio::time::Instant::now() + RECALL_DEADLINE;
    let watchdog_control = Arc::clone(&control);
    let watchdog = tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        watchdog_control.cancel_and_interrupt();
    });
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit; // retained until this blocking thread actually exits
        query_existing_views(worker_home, worker_prompt, worker_control)
    });

    SessionStartRecallPreload {
        home,
        prompt_fingerprint,
        binding_fingerprint,
        state: PreloadState::Running(RecallWorker {
            control,
            task,
            watchdog,
            deadline,
        }),
    }
}

impl SessionStartRecallPreload {
    /// Consume exactly once for the same local subject, home, session binding,
    /// and prompt.  This awaits blocking work without parking the Tokio worker.
    pub(crate) async fn consume(
        &mut self,
        subject: &crate::cli::chat::LocalChatCommunicationSubject,
        home: &Path,
        session_binding: &str,
        prompt: &str,
    ) -> SessionStartRecallOutcome {
        let matches = binding_fingerprint(subject, session_binding)
            .map(|binding| {
                home == self.home.as_path()
                    && binding == self.binding_fingerprint
                    && match self.prompt_fingerprint {
                        Some(expected) => {
                            crate::tokens::budget::count_tokens_upper_bound(prompt)
                                <= MAX_PROMPT_TOKENS
                                && fingerprint(b"NEOTH/session-start-recall/prompt/v1", prompt)
                                    == expected
                        }
                        None => {
                            crate::tokens::budget::count_tokens_upper_bound(prompt)
                                > MAX_PROMPT_TOKENS
                        }
                    }
            })
            .unwrap_or(false);
        if !matches {
            return SessionStartRecallOutcome::Stale(RecallPreloadStale::BindingMismatch);
        }

        let state = std::mem::replace(&mut self.state, PreloadState::Consumed);
        match state {
            PreloadState::Immediate(outcome) => outcome,
            PreloadState::Consumed => {
                SessionStartRecallOutcome::Failed(RecallPreloadFailure::AlreadyConsumed)
            }
            PreloadState::Running(worker) => match await_worker(worker).await {
                Ok(WorkerCompletion::Queried {
                    reader,
                    observed_data_version,
                    output,
                }) => match start_revalidation(reader, observed_data_version, output) {
                    Ok(worker) => match await_worker(worker).await {
                        Ok(WorkerCompletion::Queried { output, .. }) => {
                            SessionStartRecallOutcome::Ready { output }
                        }
                        Ok(WorkerCompletion::NoData(reason)) => {
                            SessionStartRecallOutcome::NoData(reason)
                        }
                        Ok(WorkerCompletion::Stale(reason)) => {
                            SessionStartRecallOutcome::Stale(reason)
                        }
                        Ok(WorkerCompletion::Failed(reason)) | Err(reason) => {
                            SessionStartRecallOutcome::Failed(reason)
                        }
                    },
                    Err(reason) => SessionStartRecallOutcome::Failed(reason),
                },
                Ok(WorkerCompletion::NoData(reason)) => SessionStartRecallOutcome::NoData(reason),
                Ok(WorkerCompletion::Stale(reason)) => SessionStartRecallOutcome::Stale(reason),
                Ok(WorkerCompletion::Failed(reason)) | Err(reason) => {
                    SessionStartRecallOutcome::Failed(reason)
                }
            },
        }
    }
}

impl Drop for SessionStartRecallPreload {
    fn drop(&mut self) {
        if let PreloadState::Running(worker) =
            std::mem::replace(&mut self.state, PreloadState::Consumed)
        {
            retire_worker(worker);
        }
    }
}

fn immediate(
    home: PathBuf,
    prompt_fingerprint: Option<[u8; 32]>,
    binding_fingerprint: [u8; 32],
    outcome: SessionStartRecallOutcome,
) -> SessionStartRecallPreload {
    SessionStartRecallPreload {
        home,
        prompt_fingerprint,
        binding_fingerprint,
        state: PreloadState::Immediate(outcome),
    }
}

async fn await_worker(
    worker: RecallWorker,
) -> std::result::Result<WorkerCompletion, RecallPreloadFailure> {
    let mut guard = WorkerGuard(Some(worker));
    let remaining = guard
        .0
        .as_ref()
        .expect("worker retained")
        .deadline
        .saturating_duration_since(tokio::time::Instant::now());
    let first_wait = {
        let task = &mut guard.0.as_mut().expect("worker retained").task;
        tokio::time::timeout(remaining, task).await
    };
    match first_wait {
        Ok(Ok(completion)) => {
            let worker = guard.0.take().expect("worker retained");
            let deadline_cancelled = worker.control.cancelled();
            worker.watchdog.abort();
            // The interrupt can complete the join before timeout polls its
            // timer. Preserve successful pre-deadline results, but report the
            // same deadline cause for both cancellation scheduling orders.
            if deadline_cancelled
                && matches!(
                    completion,
                    WorkerCompletion::Failed(RecallPreloadFailure::Cancelled)
                )
            {
                Err(RecallPreloadFailure::Deadline)
            } else {
                Ok(completion)
            }
        }
        Ok(Err(_)) => {
            guard.0.take().expect("worker retained").watchdog.abort();
            Err(RecallPreloadFailure::Join)
        }
        Err(_) => {
            guard
                .0
                .as_ref()
                .expect("worker retained")
                .control
                .cancel_and_interrupt();
            let grace = {
                let task = &mut guard.0.as_mut().expect("worker retained").task;
                tokio::time::timeout(INTERRUPT_GRACE, task).await
            };
            match grace {
                Ok(Ok(_)) | Ok(Err(_)) => {
                    guard.0.take().expect("worker retained").watchdog.abort();
                    Err(RecallPreloadFailure::Deadline)
                }
                Err(_) => {
                    let worker = guard.0.take().expect("worker retained");
                    retire_worker(worker);
                    Err(RecallPreloadFailure::Deadline)
                }
            }
        }
    }
}

/// Makes cancellation safe if an awaiting chat task itself is cancelled.
struct WorkerGuard(Option<RecallWorker>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            retire_worker(worker);
        }
    }
}

fn start_revalidation(
    reader: Box<ExistingViewsReader>,
    observed_data_version: i64,
    output: crate::cli::recall::RecallOutput,
) -> std::result::Result<RecallWorker, RecallPreloadFailure> {
    let permit = Arc::clone(permits())
        .try_acquire_owned()
        .map_err(|_| RecallPreloadFailure::Capacity)?;
    let control = Arc::new(WorkerControl::new());
    let worker_control = Arc::clone(&control);
    let deadline = tokio::time::Instant::now() + RECALL_DEADLINE;
    let watchdog_control = Arc::clone(&control);
    let watchdog = tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        watchdog_control.cancel_and_interrupt();
    });
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        revalidate_for_consumption(reader, observed_data_version, output, worker_control)
    });
    Ok(RecallWorker {
        control,
        task,
        watchdog,
        deadline,
    })
}

fn query_existing_views(
    home: PathBuf,
    prompt: String,
    control: Arc<WorkerControl>,
) -> WorkerCompletion {
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    let Some(reader) = (match ExistingViewsReader::open_existing(&home) {
        Ok(reader) => reader,
        Err(_) => return WorkerCompletion::Failed(RecallPreloadFailure::Open),
    }) else {
        return WorkerCompletion::NoData(RecallPreloadEmpty::Missing);
    };
    let reader = Box::new(reader);
    install_query_cancellation(&reader.conn, &control);
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    if reader
        .conn
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
        .is_err()
    {
        return WorkerCompletion::Failed(RecallPreloadFailure::ReadOnlyLimit);
    }
    if reader.conn.busy_timeout(Duration::from_millis(25)).is_err() {
        return WorkerCompletion::Failed(RecallPreloadFailure::ReadOnlyLimit);
    }
    let before = match reader.checked_data_version() {
        Ok(version) => version,
        Err(_) => return WorkerCompletion::Stale(RecallPreloadStale::IdentityChanged),
    };
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    let plan = crate::memory::region_router::route_query(&prompt);
    let mut output = match crate::cli::recall::query_three_lanes_checked(
        &reader.conn,
        &plan,
        &prompt,
        RECALL_LANE_LIMIT,
    ) {
        Ok(output) => output,
        Err(_) if control.cancelled() => {
            return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
        }
        Err(_) => return WorkerCompletion::Failed(RecallPreloadFailure::Query),
    };
    let after = match reader.checked_data_version() {
        Ok(version) => version,
        Err(_) => return WorkerCompletion::Stale(RecallPreloadStale::IdentityChanged),
    };
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    if before != after {
        return WorkerCompletion::Stale(RecallPreloadStale::DataVersionChanged);
    }
    cap_recall_source_before_handoff(&mut output);
    WorkerCompletion::Queried {
        reader,
        observed_data_version: after,
        output,
    }
}

fn revalidate_for_consumption(
    reader: Box<ExistingViewsReader>,
    observed_data_version: i64,
    output: crate::cli::recall::RecallOutput,
    control: Arc<WorkerControl>,
) -> WorkerCompletion {
    // The retained reader must use this stage's fresh deadline, not the
    // potentially expired callback from a successfully completed preload.
    install_query_cancellation(&reader.conn, &control);
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    let current = reader.checked_data_version();
    if control.cancelled() {
        return WorkerCompletion::Failed(RecallPreloadFailure::Cancelled);
    }
    match current {
        Ok(current) if current == observed_data_version => {
            if output.is_empty() {
                WorkerCompletion::NoData(RecallPreloadEmpty::Empty)
            } else {
                WorkerCompletion::Queried {
                    reader,
                    observed_data_version,
                    output,
                }
            }
        }
        Ok(_) => WorkerCompletion::Stale(RecallPreloadStale::DataVersionChanged),
        Err(_) => WorkerCompletion::Stale(RecallPreloadStale::IdentityChanged),
    }
}

/// Existing-only generic `views.db` reader.  It intentionally has no access
/// to `store::open`, which can create/migrate a database.
struct ExistingViewsReader {
    home_parent: crate::skills::store::BoundDirectory,
    home: Dir,
    home_identity: crate::skills::store::BoundDirectoryChild,
    home_name: std::ffi::OsString,
    home_display: PathBuf,
    views: crate::skills::store::BoundChildObject,
    conn: Connection,
}

impl ExistingViewsReader {
    fn open_existing(home: &Path) -> Result<Option<Self>> {
        let parent_path = home.parent().context("recall home has no parent")?;
        let trusted_anchor = parent_path.parent().unwrap_or(parent_path);
        let Some(home_parent) = crate::skills::store::open_bound_directory_from_trusted_anchor(
            trusted_anchor,
            parent_path,
            false,
            "existing local recall parent",
        )?
        else {
            return Ok(None);
        };
        let home_name = home
            .file_name()
            .context("recall home has no final directory name")?
            .to_os_string();
        let home_display = home.to_path_buf();
        let home_open = crate::skills::store::open_bound_real_child_dir(
            &home_parent.dir,
            &home_name,
            &home_display,
        );
        let (home, home_identity) = match home_open {
            Ok(bound) => bound,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let name = std::ffi::OsStr::new("views.db");
        match home.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect existing local recall database"),
            Ok(_) => {}
        }
        let display = home_display.join(name);
        let (_file, views) = crate::skills::store::open_bound_regular_file(&home, name, &display)?;
        let conn = Connection::open_with_flags(
            &display,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open existing local recall database read-only")?;
        conn.pragma_update(None, "query_only", true)?;
        let reader = Self {
            home_parent,
            home,
            home_identity,
            home_name,
            home_display,
            views,
            conn,
        };
        reader.checked_data_version()?;
        Ok(Some(reader))
    }

    fn checked_data_version(&self) -> Result<i64> {
        self.validate_identity()?;
        let before = self.data_version()?;
        self.validate_identity()?;
        let after = self.data_version()?;
        ensure!(
            before == after,
            "local recall views changed during read-only identity check"
        );
        Ok(after)
    }

    fn data_version(&self) -> Result<i64> {
        self.conn
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .context("read local recall database version")
    }

    fn validate_identity(&self) -> Result<()> {
        ensure!(
            self.home_identity.matches_directory_child(
                &self.home_parent.dir,
                &self.home_name,
                &self.home_display,
            )?,
            "local recall home identity changed"
        );
        ensure!(
            self.views.matches_regular_file_child_readonly(
                &self.home,
                std::ffi::OsStr::new("views.db"),
                &self.home_display.join("views.db"),
            )?,
            "local recall database identity changed"
        );
        Ok(())
    }
}

fn binding_fingerprint(
    _subject: &crate::cli::chat::LocalChatCommunicationSubject,
    session_binding: &str,
) -> Result<[u8; 32]> {
    ensure!(
        !session_binding.is_empty() && session_binding.len() <= MAX_SESSION_BINDING_BYTES,
        "invalid local session recall binding"
    );
    Ok(fingerprint(
        b"NEOTH/session-start-recall/operator-session/v1",
        session_binding,
    ))
}

fn fingerprint(domain: &[u8], value: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    digest.finalize().into()
}

/// Bound source data before it leaves the worker.  This operates on the actual
/// three-lane `RecallOutput`; it never manufactures labels, providers, or
/// operator claims.  The chat renderer remains responsible for deduplication,
/// canonical untrusted-context rendering, and its 16 KiB full-wire cap.
fn cap_recall_source_before_handoff(output: &mut crate::cli::recall::RecallOutput) {
    let mut remaining = usize::try_from(MAX_PRELOADED_SOURCE_TOKENS).unwrap_or(usize::MAX);
    for hit in output
        .canonical
        .iter_mut()
        .chain(output.episodes.iter_mut())
    {
        trim_utf8_to_budget(&mut hit.text, &mut remaining);
    }
    for line in &mut output.contradictions {
        trim_utf8_to_budget(&mut line.statement_a, &mut remaining);
        trim_utf8_to_budget(&mut line.statement_b, &mut remaining);
    }
    debug_assert!(
        recall_source_bytes(output)
            <= usize::try_from(MAX_PRELOADED_SOURCE_TOKENS).unwrap_or(usize::MAX)
    );
}

fn trim_utf8_to_budget(value: &mut String, remaining: &mut usize) {
    let keep = value.len().min(*remaining);
    let mut boundary = keep;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    *remaining -= boundary;
}

fn recall_source_bytes(output: &crate::cli::recall::RecallOutput) -> usize {
    output
        .canonical
        .iter()
        .chain(output.episodes.iter())
        .map(|hit| hit.text.len())
        .chain(
            output
                .contradictions
                .iter()
                .flat_map(|line| [line.statement_a.len(), line.statement_b.len()]),
        )
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn preload_test_gate() -> &'static tokio::sync::Mutex<()> {
        static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        GATE.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn subject() -> crate::cli::chat::LocalChatCommunicationSubject {
        crate::cli::chat::LocalChatCommunicationSubject::for_test()
    }

    fn seeded_home() -> TempDir {
        let home = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1, 'bounded preload remembers rust', 'preload-rust', 0.9, 0)",
            [],
        )
        .unwrap();
        drop(conn);
        home
    }

    #[tokio::test]
    async fn existing_seeded_store_is_read_only_and_ready() {
        let _gate = preload_test_gate().lock().await;
        let home = seeded_home();
        let reader = ExistingViewsReader::open_existing(home.path())
            .unwrap()
            .unwrap();
        assert!(reader.conn.execute("DELETE FROM idx_episode", []).is_err());
        assert_eq!(
            reader
                .conn
                .query_row("SELECT count(*) FROM idx_episode", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(reader);
        let local = subject();
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator\0session-1",
            "rust",
        );
        let outcome = preload
            .consume(&local, home.path(), "operator\0session-1", "rust")
            .await;
        match outcome {
            SessionStartRecallOutcome::Ready { output } => {
                assert!(
                    !output.is_empty(),
                    "seeded checked recall must carry actual output"
                );
            }
            _ => panic!("seeded read-only recall was not ready"),
        }
    }

    #[tokio::test]
    async fn missing_home_is_no_data_and_never_births_sqlite_or_wal() {
        let _gate = preload_test_gate().lock().await;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("missing-home");
        let local = subject();
        let mut preload =
            start_session_recall_preload(&local, home.clone(), "operator\0session-1", "rust");
        let wrong_home = home.join("other-home");
        assert!(matches!(
            preload
                .consume(&local, &wrong_home, "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::Stale(RecallPreloadStale::BindingMismatch)
        ));
        assert!(matches!(
            preload
                .consume(&local, &home, "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::NoData(RecallPreloadEmpty::Missing)
        ));
        assert!(!home.exists());
        assert!(!home.join("views.db").exists());
        assert!(!home.join("wal").exists());
    }

    #[tokio::test]
    async fn mismatched_prompt_does_not_consume_and_repeat_does() {
        let _gate = preload_test_gate().lock().await;
        let home = seeded_home();
        let local = subject();
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator\0session-1",
            "rust",
        );
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-2", "rust")
                .await,
            SessionStartRecallOutcome::Stale(RecallPreloadStale::BindingMismatch)
        ));
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-1", "other")
                .await,
            SessionStartRecallOutcome::Stale(RecallPreloadStale::BindingMismatch)
        ));
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::Ready { .. }
        ));
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::Failed(RecallPreloadFailure::AlreadyConsumed)
        ));
    }

    #[tokio::test]
    async fn empty_query_becomes_stale_if_views_change_before_consumption() {
        let _gate = preload_test_gate().lock().await;
        let home = seeded_home();
        let writer = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        let local = subject();
        let prompt = "unfindable-recall-topic";
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator-session",
            prompt,
        );
        // Wait for the actual checked all-lane query to finish before the
        // writer commits. An early Empty handoff that discards the reader
        // would incorrectly survive this subsequent commit.
        let PreloadState::Running(worker) = &preload.state else {
            panic!("non-skip recall must start the existing-store query");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !worker.task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("small recall fixture must finish");
        writer.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (2, 1, 2, 'unfindable-recall-topic', 'later-topic', 0.8, 0)",
            [],
        ).unwrap();
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator-session", prompt)
                .await,
            SessionStartRecallOutcome::Stale(RecallPreloadStale::DataVersionChanged)
        ));
    }

    #[tokio::test]
    async fn checked_query_error_never_becomes_empty() {
        let _gate = preload_test_gate().lock().await;
        let home = seeded_home();
        let writer = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        writer.execute("DROP TABLE idx_groundtruth", []).unwrap();
        drop(writer);
        let local = subject();
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator\0session-1",
            "rust",
        );
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::Failed(RecallPreloadFailure::Query)
        ));
    }

    #[tokio::test]
    async fn oversized_prompt_reaches_skipped_without_copying_or_io() {
        let _gate = preload_test_gate().lock().await;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("absent");
        let local = subject();
        let prompt = "x".repeat(usize::try_from(MAX_PROMPT_TOKENS).unwrap() + 1);
        let mut preload =
            start_session_recall_preload(&local, home.clone(), "operator\0session-1", &prompt);
        assert!(matches!(
            preload
                .consume(&local, &home, "operator\0session-1", &prompt)
                .await,
            SessionStartRecallOutcome::NoData(RecallPreloadEmpty::Skipped)
        ));
        assert!(!home.exists());
    }

    #[tokio::test]
    async fn successful_checked_empty_is_distinct_from_missing_and_skip() {
        let _gate = preload_test_gate().lock().await;
        let home = tempfile::tempdir().unwrap();
        drop(crate::memory::store::open(&home.path().join("views.db")).unwrap());
        let local = subject();
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator\0session-1",
            "unfindable-recall-topic",
        );
        assert!(matches!(
            preload
                .consume(
                    &local,
                    home.path(),
                    "operator\0session-1",
                    "unfindable-recall-topic",
                )
                .await,
            SessionStartRecallOutcome::NoData(RecallPreloadEmpty::Empty)
        ));
    }

    #[test]
    fn retained_home_binding_rejects_or_prevents_replacement() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        drop(crate::memory::store::open(&home.join("views.db")).unwrap());
        let reader = ExistingViewsReader::open_existing(&home).unwrap().unwrap();
        let old = root.path().join("old-home");
        let rename = std::fs::rename(&home, &old);
        #[cfg(windows)]
        if let Err(error) = &rename {
            assert_eq!(
                error.raw_os_error(),
                Some(32),
                "expected retained-handle sharing violation"
            );
            assert!(reader.checked_data_version().is_ok());
            assert!(!old.exists());
            drop(reader);
            // Prove the retained reader caused the rejection, rather than
            // accepting an unrelated permission or path failure as a pass.
            std::fs::rename(&home, &old).expect("released handles permit the same rename");
            return;
        }
        rename.unwrap();
        std::fs::create_dir(&home).unwrap();
        drop(crate::memory::store::open(&home.join("views.db")).unwrap());
        assert!(reader.checked_data_version().is_err());
    }

    #[test]
    fn source_cap_is_utf8_safe_and_matches_token_upper_bound() {
        let mut output = crate::cli::recall::RecallOutput {
            canonical: vec![crate::memory::views::EpisodeHit {
                event_id: 1,
                event_type: 1,
                ts_ns: 1,
                text: "é".repeat(10_000),
                text_hash: "h".into(),
                channel: None,
                sender_id: None,
                operator_id: None,
                tier: "hot".into(),
                importance: None,
                access_count: 0,
                trust: 1,
            }],
            ..Default::default()
        };
        cap_recall_source_before_handoff(&mut output);
        assert!(
            output.canonical[0]
                .text
                .is_char_boundary(output.canonical[0].text.len())
        );
        assert!(
            recall_source_bytes(&output) <= usize::try_from(MAX_PRELOADED_SOURCE_TOKENS).unwrap()
        );
    }

    #[tokio::test]
    async fn recursive_sql_interrupt_obeys_deadline_seam() {
        let _gate = preload_test_gate().lock().await;
        let home = seeded_home();
        let local_permits = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&local_permits).try_acquire_owned().unwrap();
        let control = Arc::new(WorkerControl::new());
        let worker_control = Arc::clone(&control);
        let deadline = tokio::time::Instant::now() + RECALL_DEADLINE;
        let watchdog_control = Arc::clone(&control);
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            watchdog_control.cancel_and_interrupt();
        });
        let worker_home = home.path().to_path_buf();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let reader = ExistingViewsReader::open_existing(&worker_home)
                .unwrap()
                .unwrap();
            install_query_cancellation(&reader.conn, &worker_control);
            let result: rusqlite::Result<i64> = reader.conn.query_row(
                "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 9223372036854775807) SELECT max(x) FROM n",
                [],
                |row| row.get(0),
            );
            assert!(result.is_err());
            WorkerCompletion::Failed(RecallPreloadFailure::Cancelled)
        });
        assert!(matches!(
            await_worker(RecallWorker {
                control,
                task,
                watchdog,
                deadline,
            })
            .await,
            Err(RecallPreloadFailure::Deadline)
        ));
    }

    #[test]
    fn query_started_after_cancel_or_deadline_is_interrupted_by_progress_guard() {
        let home = seeded_home();
        for elapsed_without_watchdog in [false, true] {
            let reader = ExistingViewsReader::open_existing(home.path())
                .unwrap()
                .unwrap();
            let mut control = WorkerControl::new();
            if elapsed_without_watchdog {
                control.deadline = std::time::Instant::now() - Duration::from_millis(1);
            }
            let control = Arc::new(control);
            install_query_cancellation(&reader.conn, &control);
            if elapsed_without_watchdog {
                assert!(!control.cancelled.load(Ordering::Acquire));
            } else {
                // No SQL is active: the interrupt alone is deliberately not
                // sufficient. The later VM callback must observe the flag.
                control.cancel_and_interrupt();
            }
            let result: rusqlite::Result<i64> = reader.conn.query_row(
                "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 10000) SELECT max(x) FROM n",
                [], |row| row.get(0),
            );
            assert!(
                matches!(result, Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::OperationInterrupted)
            );
        }
    }

    #[tokio::test]
    async fn revalidation_replaces_the_completed_preloads_expired_progress_guard() {
        let home = seeded_home();
        let reader = ExistingViewsReader::open_existing(home.path())
            .unwrap()
            .unwrap();
        let version = reader.checked_data_version().unwrap();
        let output = crate::cli::recall::query_three_lanes_checked(
            &reader.conn,
            &crate::memory::region_router::route_query("rust"),
            "rust",
            RECALL_LANE_LIMIT,
        )
        .unwrap();
        assert!(!output.is_empty());
        let mut expired = WorkerControl::new();
        expired.deadline = std::time::Instant::now() - Duration::from_millis(1);
        install_query_cancellation(&reader.conn, &Arc::new(expired));
        let completion = revalidate_for_consumption(
            Box::new(reader),
            version,
            output,
            Arc::new(WorkerControl::new()),
        );
        let WorkerCompletion::Queried { reader, .. } = completion else {
            panic!("fresh revalidation must replace the expired preload deadline");
        };
        let result: i64 = reader.conn.query_row(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 10000) SELECT max(x) FROM n",
            [], |row| row.get(0),
        ).expect("the retained connection must use the new progress guard");
        assert_eq!(result, 10000);
    }

    #[tokio::test]
    async fn completed_join_normalizes_cancelled_deadline_but_preserves_ready_data() {
        async fn completed_worker(completion: WorkerCompletion) -> RecallWorker {
            let task = tokio::task::spawn_blocking(move || completion);
            tokio::time::timeout(Duration::from_secs(2), async {
                while !task.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("small fixture completion must finish");
            let control = Arc::new(WorkerControl::new());
            control.cancel_and_interrupt();
            RecallWorker {
                control,
                task,
                watchdog: tokio::spawn(async {}),
                deadline: tokio::time::Instant::now() - Duration::from_millis(1),
            }
        }

        assert!(matches!(
            await_worker(
                completed_worker(WorkerCompletion::Failed(RecallPreloadFailure::Cancelled)).await
            )
            .await,
            Err(RecallPreloadFailure::Deadline)
        ));
        let home = seeded_home();
        let completion = query_existing_views(
            home.path().to_path_buf(),
            "rust".to_owned(),
            Arc::new(WorkerControl::new()),
        );
        match await_worker(completed_worker(completion).await).await {
            Ok(WorkerCompletion::Queried { output, .. }) => assert!(!output.is_empty()),
            _ => panic!("a completed recall must survive a later watchdog notification"),
        }
    }

    #[tokio::test]
    async fn actual_start_reports_capacity_when_bounded_pool_is_saturated() {
        let _gate = preload_test_gate().lock().await;
        let one = Arc::clone(permits()).try_acquire_owned().unwrap();
        let two = Arc::clone(permits()).try_acquire_owned().unwrap();
        let home = seeded_home();
        let local = subject();
        let mut preload = start_session_recall_preload(
            &local,
            home.path().to_path_buf(),
            "operator\0session-1",
            "rust",
        );
        assert!(matches!(
            preload
                .consume(&local, home.path(), "operator\0session-1", "rust")
                .await,
            SessionStartRecallOutcome::Failed(RecallPreloadFailure::Capacity)
        ));
        drop((one, two));
    }
}
