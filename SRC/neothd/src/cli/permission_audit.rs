//! Bounded, required audit ownership for one-shot CLI permission boundaries.
//!
//! A live daemon owns the canonical WAL and is reached through its
//! authenticated audit RPC.  Without a live daemon, a one-shot command owns a
//! writer for its whole protected effect.  Callers must keep this session alive
//! until the effect has completed, then call [`RequiredPermissionAudit::finish`]
//! before reporting success.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::permissions::PermissionAuditSink;
use crate::wal::writer::{WalWriterCompletion, WalWriterHandle};

#[cfg(not(test))]
const REQUIRED_PERMISSION_AUDIT_FINALIZE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);
#[cfg(test)]
const REQUIRED_PERMISSION_AUDIT_FINALIZE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(250);

/// One required-audit destination with an explicitly bounded writer lifetime.
///
/// The borrowed [`PermissionAuditSink`] is intentionally obtained only from
/// this owner.  That lets a command pass the same local writer through all of
/// its admission stages without accidentally creating a second decision WAL.
pub(crate) enum RequiredPermissionAudit {
    DaemonRpc {
        home: PathBuf,
    },
    Writer {
        writer: Option<WalWriterHandle>,
        completion: Option<WalWriterCompletion>,
        /// Retained independently from `completion` so cancellation while
        /// `finish()` awaits can still abort the actual writer task.
        abort: tokio::task::AbortHandle,
    },
}

impl Drop for RequiredPermissionAudit {
    fn drop(&mut self) {
        let Self::Writer { writer, abort, .. } = self else {
            return;
        };
        drop(writer.take());
        // `JoinHandle` detaches when dropped. This abort handle remains owned
        // even if `finish()` already moved `completion` into wait_bounded, so
        // cancellation cannot leave an unaudited one-shot task running.
        abort.abort();
    }
}

impl RequiredPermissionAudit {
    /// Select the authenticated daemon audit RPC when that daemon owns this
    /// exact home; otherwise open a home-bound standalone writer.  A live
    /// daemon is never silently bypassed: an unavailable RPC then makes the
    /// required Gate append fail before the protected effect.
    pub(crate) fn open(home: &Path, surface: &'static str) -> Result<Self> {
        let daemon_live = crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))
            .with_context(|| format!("inspect daemon ownership for {}", home.display()))?
            .is_some();
        if daemon_live {
            return Ok(Self::DaemonRpc {
                home: home.to_path_buf(),
            });
        }

        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).with_context(|| {
            format!("create required audit WAL directory {}", wal_dir.display())
        })?;
        let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, surface);
        let (writer, completion) =
            crate::wal::writer::spawn_for_home_with_completion(segment, home.to_path_buf())
                .with_context(|| format!("open required home-bound audit writer for {surface}"))?;
        let abort = completion.abort_handle();
        Ok(Self::Writer {
            writer: Some(writer),
            completion: Some(completion),
            abort,
        })
    }

    /// Borrow the sole audit destination for a canonical [`crate::permissions::Gate`].
    pub(crate) fn sink(&self) -> PermissionAuditSink<'_> {
        match self {
            Self::DaemonRpc { home } => PermissionAuditSink::DaemonRpc(home),
            Self::Writer { writer, .. } => writer
                .as_ref()
                .map(PermissionAuditSink::Writer)
                .unwrap_or(PermissionAuditSink::None),
        }
    }

    #[cfg(test)]
    pub(crate) fn writer_clone_for_test(&self) -> Option<WalWriterHandle> {
        match self {
            Self::Writer { writer, .. } => writer.clone(),
            Self::DaemonRpc { .. } => None,
        }
    }

    /// Release a standalone writer under one bounded deadline and surface its
    /// final synchronization error. A timeout aborts and reaps the underlying
    /// writer task even if another clone was retained. Daemon-RPC sessions
    /// require no local finalization.
    pub(crate) async fn finish(mut self) -> Result<()> {
        let Self::Writer {
            writer, completion, ..
        } = &mut self
        else {
            return Ok(());
        };
        drop(writer.take());
        completion
            .take()
            .context("required audit writer completion is absent")?
            .wait_bounded(REQUIRED_PERMISSION_AUDIT_FINALIZE_TIMEOUT)
            .await
            .context("finalize required home-bound permission audit WAL writer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finalization_timeout_aborts_writer_even_with_retained_clone() {
        let home = tempfile::tempdir().unwrap();
        let session =
            RequiredPermissionAudit::open(home.path(), "permission-audit-timeout").unwrap();
        let retained = match &session {
            RequiredPermissionAudit::Writer { writer, .. } => writer.as_ref().unwrap().clone(),
            RequiredPermissionAudit::DaemonRpc { .. } => panic!("temp home has no live daemon"),
        };
        let started = tokio::time::Instant::now();
        let error = session.finish().await.unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "bounded finalization must not wait for a retained sender clone"
        );
        assert!(format!("{error:#}").contains("did not finalize"));
        let payload = b"after-abort".to_vec();
        let header = crate::wal::HeaderBuilder::new(0xE1, &payload).build();
        assert!(retained.append(header, payload).await.is_err());
        drop(retained);
        let reopened =
            RequiredPermissionAudit::open(home.path(), "permission-audit-reopen").unwrap();
        reopened
            .finish()
            .await
            .expect("aborted writer must release its segment and rewrite locks for a new session");
    }

    #[tokio::test]
    async fn dropped_session_aborts_writer_instead_of_detaching_it() {
        let home = tempfile::tempdir().unwrap();
        let session = RequiredPermissionAudit::open(home.path(), "permission-audit-drop").unwrap();
        let retained = match &session {
            RequiredPermissionAudit::Writer { writer, .. } => writer.as_ref().unwrap().clone(),
            RequiredPermissionAudit::DaemonRpc { .. } => panic!("temp home has no live daemon"),
        };
        drop(session);
        let payload = b"after-drop".to_vec();
        let header = crate::wal::HeaderBuilder::new(0xE2, &payload).build();
        let append = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            retained.append(header, payload),
        )
        .await
        .expect("aborted writer must release the retained sender promptly");
        assert!(append.is_err());
    }

    #[tokio::test]
    async fn cancelled_finish_aborts_writer_and_releases_home_authority() {
        let home = tempfile::tempdir().unwrap();
        let session =
            RequiredPermissionAudit::open(home.path(), "permission-audit-cancel").unwrap();
        let retained = match &session {
            RequiredPermissionAudit::Writer { writer, .. } => writer.as_ref().unwrap().clone(),
            RequiredPermissionAudit::DaemonRpc { .. } => panic!("temp home has no live daemon"),
        };

        let mut finish = Box::pin(session.finish());
        tokio::select! {
            result = &mut finish => panic!("retained sender unexpectedly finalized: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        drop(finish);

        let payload = b"after-cancelled-finish".to_vec();
        let header = crate::wal::HeaderBuilder::new(0xE3, &payload).build();
        let append = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            retained.append(header, payload),
        )
        .await
        .expect("cancelling finish must abort the retained sender promptly");
        assert!(append.is_err());
        drop(retained);

        let reopened = RequiredPermissionAudit::open(home.path(), "permission-audit-cancel-reopen")
            .expect("cancelled finalization must release the home writer authority");
        reopened.finish().await.unwrap();
    }
}
