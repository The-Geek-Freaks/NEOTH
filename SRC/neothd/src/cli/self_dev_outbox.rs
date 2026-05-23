//! Self-dev WAL outbox + daemon drain task.
//!
//! The `neoth self-dev` CLI commands run without a `WalWriterHandle`
//! (the daemon owns the WAL segment exclusively — opening a second
//! writer from the CLI process would race the fsync chain). The
//! outbox closes that gap by giving CLI a place to enqueue
//! pending WAL events; the daemon then drains the queue every
//! `DRAIN_INTERVAL` (default 5s) and emits real
//! `EVENT_TYPE_SELF_DEV_PROPOSED` / `..._ACCEPTED` / `..._DECLINED`
//! frames into the WAL.
//!
//! Wire format: one JSON object per line (JSONL) at
//! `<home>/self_dev/pending_events.jsonl`. Append-only writes from
//! the CLI are crash-safe (each line is `serde_json::to_writer` +
//! newline, atomic at the kernel level for sub-PIPE_BUF sizes).
//! The daemon drains by reading the file, emitting each line as a
//! WAL frame, then truncating the file to zero. Truncation is
//! best-effort + idempotent — a crash between emit and truncate
//! re-emits on next drain (operator sees a duplicate event in WAL
//! audit, which is the safer failure mode than silent loss).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use crate::profile::self_dev::SelfDevProposal;
use crate::wal::events::{
    EVENT_TYPE_SELF_DEV_ACCEPTED, EVENT_TYPE_SELF_DEV_DECLINED, EVENT_TYPE_SELF_DEV_PROPOSED,
};
use crate::wal::writer::WalWriterHandle;

/// Daemon drain interval. Operator-visible latency between CLI
/// invocation and the WAL frame landing.
pub const DRAIN_INTERVAL: Duration = Duration::from_secs(5);

/// Kind discriminator on the wire. Mirrors the three WAL event
/// types this outbox carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Proposed,
    Accepted,
    Declined,
}

/// One queued event. `Proposed` carries the full proposal so the
/// daemon emits the 0x1C payload verbatim; `Accepted` / `Declined`
/// carry just the proposal id + (for Declined) the reason.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingEvent {
    pub kind: PendingKind,
    pub proposal_id: String,
    pub ts_unix: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal: Option<SelfDevProposal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl PendingEvent {
    pub fn proposed(proposal: SelfDevProposal, ts_unix: i64) -> Self {
        Self {
            kind: PendingKind::Proposed,
            proposal_id: proposal.id.clone(),
            ts_unix,
            proposal: Some(proposal),
            decline_reason: None,
        }
    }

    pub fn accepted(proposal_id: impl Into<String>, ts_unix: i64) -> Self {
        Self {
            kind: PendingKind::Accepted,
            proposal_id: proposal_id.into(),
            ts_unix,
            proposal: None,
            decline_reason: None,
        }
    }

    pub fn declined(
        proposal_id: impl Into<String>,
        reason: impl Into<String>,
        ts_unix: i64,
    ) -> Self {
        Self {
            kind: PendingKind::Declined,
            proposal_id: proposal_id.into(),
            ts_unix,
            proposal: None,
            decline_reason: Some(reason.into()),
        }
    }
}

/// Outbox file path inside `<home>/self_dev/`.
pub fn outbox_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("pending_events.jsonl")
}

/// Append one event to the outbox file. Creates the parent dir +
/// the file if missing. CLI calls this from accept/decline/propose;
/// the daemon drain task reads + emits + truncates.
pub async fn enqueue(home: &Path, event: &PendingEvent) -> Result<()> {
    let path = outbox_path(home);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("open append {}", path.display()))?;
    f.write_all(&line)
        .await
        .with_context(|| format!("append to {}", path.display()))?;
    f.flush().await?;
    Ok(())
}

/// Drain every pending event in the outbox. Returns the number
/// emitted. Truncates the file after successful emit so subsequent
/// drains are no-ops. Per-line parse failures log + continue —
/// a corrupted line should not block the rest of the queue.
pub async fn drain_once(home: &Path, writer: &WalWriterHandle) -> Result<usize> {
    let path = outbox_path(home);
    if !path.exists() {
        return Ok(0);
    }
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("open {}", path.display()))),
    };
    let mut reader = tokio::io::BufReader::new(file);
    let mut buf = String::new();
    let mut emitted = 0usize;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: PendingEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, line = trimmed, "self-dev outbox: skipping corrupted line");
                continue;
            }
        };
        if let Err(e) = emit_event(writer, &event).await {
            tracing::error!(error = %e, kind = ?event.kind, id = %event.proposal_id, "self-dev outbox: WAL emit failed; will retry next drain");
            // Bail without truncating so the failed event re-tries
            // on the next drain. Re-raising would crash the task;
            // returning Ok preserves the daemon's other surfaces.
            return Ok(emitted);
        }
        emitted += 1;
    }
    // All emits succeeded — truncate the outbox.
    tokio::fs::write(&path, b"")
        .await
        .with_context(|| format!("truncate {}", path.display()))?;
    Ok(emitted)
}

async fn emit_event(writer: &WalWriterHandle, event: &PendingEvent) -> Result<()> {
    match event.kind {
        PendingKind::Proposed => {
            let proposal = event
                .proposal
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("proposed event missing proposal payload"))?;
            let payload = proposal.to_proposed_payload(event.ts_unix);
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_PROPOSED, &payload).build();
            writer.append(header, payload).await?;
        }
        PendingKind::Accepted => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "proposal_id": event.proposal_id,
                "ts_unix": event.ts_unix,
            }))
            .unwrap_or_default();
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_ACCEPTED, &payload).build();
            writer.append(header, payload).await?;
        }
        PendingKind::Declined => {
            let reason = event.decline_reason.as_deref().unwrap_or("declined");
            let payload = serde_json::to_vec(&serde_json::json!({
                "proposal_id": event.proposal_id,
                "reason": reason,
                "ts_unix": event.ts_unix,
            }))
            .unwrap_or_default();
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_SELF_DEV_DECLINED, &payload).build();
            writer.append(header, payload).await?;
        }
    }
    Ok(())
}

/// Spawn the daemon-side drain task. Loops every `DRAIN_INTERVAL`,
/// calls `drain_once`, sleeps. Returns a handle the daemon awaits
/// during shutdown so the final drain lands before the WAL writer
/// closes.
pub fn spawn_drain_task(home: PathBuf, writer: WalWriterHandle) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DRAIN_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match drain_once(&home, &writer).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(emitted = n, "self-dev outbox drained"),
                Err(e) => {
                    tracing::warn!(error = %e, "self-dev outbox drain failed; retrying next tick")
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::self_dev::ProposalKind;
    use tempfile::tempdir;

    fn fixture_proposal(id: &str) -> SelfDevProposal {
        SelfDevProposal {
            id: id.into(),
            kind: ProposalKind::SwitchPreset,
            reason: "test".into(),
            confidence: 0.75,
            target: "formal".into(),
        }
    }

    #[test]
    fn outbox_path_lands_under_self_dev_subdir() {
        let p = outbox_path(Path::new("/home/x"));
        assert_eq!(p, Path::new("/home/x/self_dev/pending_events.jsonl"));
    }

    #[test]
    fn drain_interval_pinned_to_5s() {
        // Drift guard — operator-visible latency contract. Slowing
        // this down silently would surprise operators with delayed
        // WAL frames.
        assert_eq!(DRAIN_INTERVAL, Duration::from_secs(5));
    }

    #[test]
    fn pending_kind_serialises_snake_case() {
        let p = serde_json::to_string(&PendingKind::Proposed).unwrap();
        assert_eq!(p, "\"proposed\"");
        let a = serde_json::to_string(&PendingKind::Accepted).unwrap();
        assert_eq!(a, "\"accepted\"");
        let d = serde_json::to_string(&PendingKind::Declined).unwrap();
        assert_eq!(d, "\"declined\"");
    }

    #[test]
    fn proposed_builder_populates_proposal_payload() {
        let p = PendingEvent::proposed(fixture_proposal("x"), 1_700_000_000);
        assert_eq!(p.kind, PendingKind::Proposed);
        assert_eq!(p.proposal_id, "x");
        assert!(p.proposal.is_some());
        assert!(p.decline_reason.is_none());
    }

    #[test]
    fn accepted_builder_omits_proposal_and_reason() {
        let a = PendingEvent::accepted("x", 1_700_000_000);
        assert_eq!(a.kind, PendingKind::Accepted);
        assert!(a.proposal.is_none());
        assert!(a.decline_reason.is_none());
    }

    #[test]
    fn declined_builder_carries_reason() {
        let d = PendingEvent::declined("x", "timeout", 1_700_000_000);
        assert_eq!(d.kind, PendingKind::Declined);
        assert_eq!(d.decline_reason.as_deref(), Some("timeout"));
    }

    #[tokio::test]
    async fn enqueue_appends_one_line_per_event_then_reread_parses() {
        let dir = tempdir().unwrap();
        enqueue(dir.path(), &PendingEvent::accepted("a", 1))
            .await
            .unwrap();
        enqueue(dir.path(), &PendingEvent::declined("b", "timeout", 2))
            .await
            .unwrap();
        let bytes = tokio::fs::read(outbox_path(dir.path())).await.unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let e1: PendingEvent = serde_json::from_str(lines[0]).unwrap();
        let e2: PendingEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e1.proposal_id, "a");
        assert_eq!(e2.proposal_id, "b");
    }

    #[tokio::test]
    async fn drain_on_missing_file_returns_zero() {
        let dir = tempdir().unwrap();
        // No WAL writer because we never reach emit_event for empty.
        // Construct via a dummy spawn to satisfy the type.
        let writer = test_writer().await;
        let n = drain_once(dir.path(), &writer).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn drain_emits_then_truncates() {
        let dir = tempdir().unwrap();
        enqueue(
            dir.path(),
            &PendingEvent::proposed(fixture_proposal("x"), 1_700_000_000),
        )
        .await
        .unwrap();
        let writer = test_writer().await;
        let n = drain_once(dir.path(), &writer).await.unwrap();
        assert_eq!(n, 1);
        // File still exists but truncated to zero bytes.
        let bytes = tokio::fs::read(outbox_path(dir.path())).await.unwrap();
        assert!(bytes.is_empty(), "outbox not truncated post-drain");
    }

    #[tokio::test]
    async fn drain_skips_corrupted_lines_and_emits_valid_ones() {
        let dir = tempdir().unwrap();
        // Manually write a mix of valid + corrupted lines.
        let path = outbox_path(dir.path());
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let valid = serde_json::to_string(&PendingEvent::accepted("good", 1)).unwrap();
        let mix = format!("{valid}\nthis is not json\n{valid}\n");
        tokio::fs::write(&path, mix).await.unwrap();
        let writer = test_writer().await;
        let n = drain_once(dir.path(), &writer).await.unwrap();
        // 2 valid lines emit; corrupted line skipped.
        assert_eq!(n, 2);
    }

    /// Helper — spin up a real WAL writer over a tempfile so the
    /// drain path actually exercises `writer.append`.
    async fn test_writer() -> WalWriterHandle {
        let dir = tempdir().unwrap();
        // Leak the tempdir so the path stays alive for the test —
        // the test itself drops at the end which terminates the
        // tokio runtime + the writer task.
        let segment = dir.keep().join("test.wal");
        let (handle, _join) = crate::wal::writer::spawn(segment).expect("spawn test wal writer");
        handle
    }
}
