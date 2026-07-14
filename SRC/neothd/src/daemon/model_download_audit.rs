//! Fail-closed audit lifecycle for implicit Hugging Face downloads.
//!
//! A live daemon receives D7/D8 over its authenticated audit RPC. A standalone
//! process owns a collision-resistant WAL segment for the entire attempt. D7
//! must be durably acknowledged before the downloader closure receives its
//! unforgeable [`ModelDownloadPermit`]; every returned outcome is closed by D8.

use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::FreedomConfig;
use crate::media::model_manager::{
    ModelDownloadAttempt, ModelDownloadAuditSink, ModelDownloadPermit, PendingModelDownloadOutcome,
};
use crate::wal::{spawn as wal_spawn, writer::WalWriterHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImplicitModelDownloadSource {
    Qwen,
    Ouro,
}

impl ImplicitModelDownloadSource {
    const fn trigger(self) -> &'static str {
        let _ = self;
        "implicit"
    }
}

enum ImplicitAuditSink {
    Daemon { home: PathBuf },
    Wal(WalWriterHandle),
}

#[async_trait::async_trait]
impl ModelDownloadAuditSink for ImplicitAuditSink {
    async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()> {
        match self {
            Self::Daemon { home } => {
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload)
                    .await
                    .context("forward mandatory implicit model-download audit frame to daemon")
            }
            Self::Wal(writer) => {
                ModelDownloadAuditSink::append_model_download(writer, event_type, payload).await
            }
        }
    }
}

struct ImplicitAuditTransport {
    sink: ImplicitAuditSink,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ImplicitAuditTransport {
    fn open() -> Result<Self> {
        let pidfile = crate::daemon::pidfile::default_pidfile();
        let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
            .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))?
            .is_some();
        if daemon_live {
            return Ok(Self {
                sink: ImplicitAuditSink::Daemon {
                    home: FreedomConfig::default_neoth_home(),
                },
                join: None,
            });
        }

        let wal_dir = FreedomConfig::default_wal_dir();
        std::fs::create_dir_all(&wal_dir).with_context(|| {
            format!(
                "create mandatory implicit model-download WAL directory {}",
                wal_dir.display()
            )
        })?;
        let segment =
            crate::wal::writer::unique_standalone_segment_path(&wal_dir, "implicit-model-download");
        let (writer, join) =
            wal_spawn(segment).context("spawn mandatory implicit model-download WAL writer")?;
        Ok(Self {
            sink: ImplicitAuditSink::Wal(writer),
            join: Some(join),
        })
    }

    async fn shutdown(self) -> Result<()> {
        let Self { sink, join } = self;
        drop(sink);
        if let Some(join) = join {
            join.await
                .context("join mandatory implicit model-download WAL writer")?;
        }
        Ok(())
    }
}

/// Run one implicit network fetch behind the canonical durable D7/D8 state
/// machine. The closure cannot be called until D7 minted its exact permit.
pub(crate) async fn run_implicit_model_download<F, Fut>(
    root: &Path,
    model_id: &str,
    source: ImplicitModelDownloadSource,
    artifacts_ready: bool,
    download: F,
) -> Result<()>
where
    F: FnOnce(ModelDownloadPermit) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let transport = ImplicitAuditTransport::open()?;
    let operation = run_implicit_model_download_with_sink(
        root,
        model_id,
        source,
        artifacts_ready,
        &transport.sink,
        download,
    )
    .await;
    let shutdown = transport.shutdown().await;
    match (operation, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(shutdown)) => Err(anyhow::anyhow!(
            "{operation:#}; additionally failed to close audit WAL: {shutdown:#}"
        )),
    }
}

async fn run_implicit_model_download_with_sink<F, Fut>(
    root: &Path,
    model_id: &str,
    source: ImplicitModelDownloadSource,
    artifacts_ready: bool,
    sink: &dyn ModelDownloadAuditSink,
    download: F,
) -> Result<()>
where
    F: FnOnce(ModelDownloadPermit) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut attempt = ModelDownloadAttempt::acquire(root, model_id, source.trigger())
        .await
        .context("acquire implicit model-download lifecycle")?;

    let had_pending = attempt.is_pending();
    if let Some(pending_outcome) = attempt.pending_outcome() {
        let replayed = attempt
            .replay_terminal(sink)
            .await
            .context("replay pending implicit MODEL_DOWNLOAD_COMPLETE")?;
        debug_assert_eq!(replayed, pending_outcome);
        if artifacts_ready && matches!(replayed, PendingModelDownloadOutcome::Ready) {
            return Ok(());
        }
    } else if artifacts_ready && !had_pending {
        return Ok(());
    }

    let permit = attempt
        .authorize_network(sink)
        .await
        .context("append mandatory implicit MODEL_DOWNLOAD_START")?;
    match download(permit).await {
        Ok(()) => attempt
            .finish_ready(sink, root)
            .await
            .context("append mandatory ready implicit MODEL_DOWNLOAD_COMPLETE"),
        Err(download_error) => match attempt
            .finish_failed(sink, &format!("{download_error:#}"))
            .await
        {
            Ok(()) => Err(download_error),
            Err(audit_error) => Err(anyhow::anyhow!(
                "implicit model download failed: {download_error:#}; terminal audit also failed: {audit_error:#}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(u8, serde_json::Value)>>,
        fail_event: Option<u8>,
    }

    #[async_trait::async_trait]
    impl ModelDownloadAuditSink for RecordingSink {
        async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()> {
            if self.fail_event == Some(event_type) {
                anyhow::bail!("injected audit failure for {event_type:#04x}");
            }
            self.events
                .lock()
                .unwrap()
                .push((event_type, serde_json::from_slice(&payload)?));
            Ok(())
        }
    }

    #[tokio::test]
    async fn audit_failure_prevents_network_closure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("qwen");
        let network_called = AtomicBool::new(false);
        let sink = RecordingSink {
            fail_event: Some(crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START),
            ..RecordingSink::default()
        };

        let result = run_implicit_model_download_with_sink(
            &root,
            "Qwen/model",
            ImplicitModelDownloadSource::Qwen,
            false,
            &sink,
            |_permit| async {
                network_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(result.is_err());
        assert!(!network_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn qwen_and_ouro_share_attempt_hash_and_terminal_closure() {
        for (source, model) in [
            (ImplicitModelDownloadSource::Qwen, "Qwen/model"),
            (ImplicitModelDownloadSource::Ouro, "ByteDance/Ouro"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("model");
            let permit_root = root.clone();
            let sink = RecordingSink::default();
            run_implicit_model_download_with_sink(
                &root,
                model,
                source,
                false,
                &sink,
                move |permit| async move { permit.require(&permit_root, model) },
            )
            .await
            .unwrap();

            let events = sink.events.lock().unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].1["trigger"], source.trigger());
            assert_eq!(events[1].1["trigger"], source.trigger());
            assert_eq!(events[0].1["attempt_id"], events[1].1["attempt_id"]);
            assert_eq!(events[0].1["attempt_sha256"], events[1].1["attempt_sha256"]);
            assert_eq!(events[0].1["attempt_sha256"].as_str().unwrap().len(), 64);
            assert_eq!(events[0].1["status"], "started");
            assert_eq!(events[1].1["status"], "ready");
        }
    }

    #[tokio::test]
    async fn download_failure_is_closed_by_failed_d8() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ouro");
        let sink = RecordingSink::default();
        let result = run_implicit_model_download_with_sink(
            &root,
            "ByteDance/Ouro",
            ImplicitModelDownloadSource::Ouro,
            false,
            &sink,
            |_permit| async { anyhow::bail!("injected network failure") },
        )
        .await;

        assert!(result.is_err());
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].1["status"], "failed");
        assert!(events[1].1["reason"].as_str().unwrap().contains("injected"));
        assert_eq!(events[0].1["attempt_id"], events[1].1["attempt_id"]);
    }

    #[tokio::test]
    async fn ready_retry_replays_d8_without_a_second_network_call() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("qwen");
        let failing_terminal = RecordingSink {
            fail_event: Some(crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE),
            ..RecordingSink::default()
        };
        assert!(
            run_implicit_model_download_with_sink(
                &root,
                "Qwen/model",
                ImplicitModelDownloadSource::Qwen,
                false,
                &failing_terminal,
                |_permit| async { Ok(()) },
            )
            .await
            .is_err()
        );

        let network_called = AtomicBool::new(false);
        let replay = RecordingSink::default();
        run_implicit_model_download_with_sink(
            &root,
            "Qwen/model",
            ImplicitModelDownloadSource::Qwen,
            true,
            &replay,
            |_permit| async {
                network_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(!network_called.load(Ordering::SeqCst));
        let events = replay.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1["status"], "ready");
    }
}
