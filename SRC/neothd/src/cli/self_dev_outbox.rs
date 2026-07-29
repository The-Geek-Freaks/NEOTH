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
//! `<home>/self_dev/pending_events.jsonl`. Enqueue and drain share a
//! process-local mutex plus a cross-process file lock. Enqueue performs a
//! private, fsynced atomic rewrite; drain atomically renames the pending
//! journal to an in-flight claim and acknowledges each successfully emitted
//! prefix with another private, fsynced atomic rewrite. Consequently an
//! append cannot be lost between a drain read and truncate, and an ordinary
//! later emit failure does not replay the already-acknowledged prefix.
//!
//! A process or power loss in the narrow interval between WAL fsync and claim
//! acknowledgement can still replay that one event. The WAL writer has no
//! transactional idempotency-key API, so this boundary is deliberately
//! at-least-once rather than risking silent audit loss.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::profile::self_dev::SelfDevProposal;
use crate::wal::events::{
    EVENT_TYPE_SELF_DEV_ACCEPTED, EVENT_TYPE_SELF_DEV_DECLINED, EVENT_TYPE_SELF_DEV_PROPOSED,
};
use crate::wal::writer::WalWriterHandle;

/// Daemon drain interval. Operator-visible latency between CLI
/// invocation and the WAL frame landing.
pub const DRAIN_INTERVAL: Duration = Duration::from_secs(5);

/// Serialises callers inside one process before the advisory OS lock. This is
/// the canonical mutex-first ordering required by `util::locked_file`.
static OUTBOX_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Kind discriminator on the wire. Mirrors the three WAL event
/// types this outbox carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Proposed,
    Accepted,
    Declined,
}

/// One queued event. `Proposed` carries the full proposal so the daemon can
/// build the canonical 0x1C payload; every emitted payload additionally carries
/// `audit_event_id` for deterministic downstream deduplication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEvent {
    pub kind: PendingKind,
    pub proposal_id: String,
    pub ts_unix: i64,
    /// Stable content-bound id carried into the WAL payload. Legacy journals
    /// omit it; the parser derives and persists it before the next mutation.
    #[serde(default)]
    pub audit_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal: Option<SelfDevProposal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl PendingEvent {
    pub fn proposed(proposal: SelfDevProposal, ts_unix: i64) -> Self {
        Self::with_derived_audit_id(Self {
            kind: PendingKind::Proposed,
            proposal_id: proposal.id.clone(),
            ts_unix,
            audit_event_id: String::new(),
            proposal: Some(proposal),
            decline_reason: None,
        })
    }

    pub fn accepted(proposal_id: impl Into<String>, ts_unix: i64) -> Self {
        Self::with_derived_audit_id(Self {
            kind: PendingKind::Accepted,
            proposal_id: proposal_id.into(),
            ts_unix,
            audit_event_id: String::new(),
            proposal: None,
            decline_reason: None,
        })
    }

    pub fn declined(
        proposal_id: impl Into<String>,
        reason: impl Into<String>,
        ts_unix: i64,
    ) -> Self {
        Self::with_derived_audit_id(Self {
            kind: PendingKind::Declined,
            proposal_id: proposal_id.into(),
            ts_unix,
            audit_event_id: String::new(),
            proposal: None,
            decline_reason: Some(reason.into()),
        })
    }

    fn with_derived_audit_id(mut event: Self) -> Self {
        event.audit_event_id = derive_audit_event_id(&event);
        event
    }
}

/// Outbox file path inside `<home>/self_dev/`.
pub fn outbox_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("pending_events.jsonl")
}

fn claim_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("pending_events.inflight.jsonl")
}

fn lock_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("pending_events.lock")
}

/// Durably enqueue one event. The complete pending journal is parsed before
/// mutation and then replaced through the canonical private atomic writer.
/// This is intentionally a bounded RMW journal rather than an unlocked append:
/// it gives Windows and Unix the same fsync and cross-process guarantees.
pub async fn enqueue(home: &Path, event: &PendingEvent) -> Result<()> {
    let _process_guard = OUTBOX_MUTEX.lock().await;
    let _file_guard = acquire_file_lock(home).await?;
    let path = outbox_path(home);
    validate_event(event).context("validate self-dev outbox event")?;
    let in_flight = read_journal_if_present(&claim_path(home))?.unwrap_or_default();
    let mut pending = read_journal_if_present(&path)?.unwrap_or_default();
    if in_flight
        .iter()
        .chain(pending.iter())
        .any(|queued| queued.audit_event_id == event.audit_event_id)
    {
        return Ok(());
    }
    pending.push(event.clone());
    persist_journal(&path, &pending)
        .with_context(|| format!("durably enqueue self-dev event in {}", path.display()))
}

/// Drain every pending event in FIFO order. A pending journal is first renamed
/// atomically to an in-flight claim. After each successful WAL append, that
/// exact event is removed from the claim before the next append is attempted.
/// Corruption fails loudly before any event from the affected journal emits;
/// the bytes remain in place for operator repair rather than being skipped.
pub async fn drain_once(home: &Path, writer: &WalWriterHandle) -> Result<usize> {
    let _process_guard = OUTBOX_MUTEX.lock().await;
    let _file_guard = acquire_file_lock(home).await?;
    let mut emitted = 0usize;

    loop {
        let claimed = match claim_next_journal(home)? {
            Some(events) => events,
            None => return Ok(emitted),
        };

        for (index, event) in claimed.iter().enumerate() {
            emit_event(writer, event).await.with_context(|| {
                format!(
                    "self-dev outbox WAL emit failed after {emitted} durable acknowledgement(s); failed event retained (kind={:?}, proposal_id={})",
                    event.kind, event.proposal_id
                )
            })?;

            persist_claim(home, &claimed[index + 1..]).with_context(|| {
                format!(
                    "acknowledge emitted self-dev event (kind={:?}, proposal_id={})",
                    event.kind, event.proposal_id
                )
            })?;
            emitted += 1;
        }
    }
}

async fn acquire_file_lock(home: &Path) -> Result<std::fs::File> {
    let path = lock_path(home);
    tokio::task::spawn_blocking(move || {
        crate::util::locked_file::lock_file_blocking(&path, "self-dev outbox")
    })
    .await
    .context("self-dev outbox lock task failed")?
}

/// Return the existing in-flight claim, or atomically claim the active journal.
/// Existing claims always drain first so events retained after a failure keep
/// FIFO order ahead of events enqueued in the meantime.
fn claim_next_journal(home: &Path) -> Result<Option<Vec<PendingEvent>>> {
    let claim = claim_path(home);
    loop {
        if let Some(events) = read_journal_if_present(&claim)? {
            if events.is_empty() {
                crate::util::atomic_write::durable_remove_file(&claim)
                    .with_context(|| format!("remove empty claim {}", claim.display()))?;
                continue;
            }
            return Ok(Some(events));
        }

        let pending_path = outbox_path(home);
        let Some(events) = read_journal_if_present(&pending_path)? else {
            return Ok(None);
        };
        if events.is_empty() {
            crate::util::atomic_write::durable_remove_file(&pending_path)
                .with_context(|| format!("remove empty journal {}", pending_path.display()))?;
            return Ok(None);
        }

        // Canonicalise and narrow permissions before the atomic move. This also
        // upgrades legacy journals created by the former unlocked append path.
        persist_journal(&pending_path, &events)
            .with_context(|| format!("prepare journal claim {}", pending_path.display()))?;
        std::fs::rename(&pending_path, &claim).with_context(|| {
            format!(
                "atomically claim self-dev journal {} as {}",
                pending_path.display(),
                claim.display()
            )
        })?;
        sync_parent_dir(&claim)?;
        return Ok(Some(events));
    }
}

fn persist_claim(home: &Path, remaining: &[PendingEvent]) -> Result<()> {
    let path = claim_path(home);
    if remaining.is_empty() {
        crate::util::atomic_write::durable_remove_file(&path)
            .with_context(|| format!("remove acknowledged claim {}", path.display()))
    } else {
        persist_journal(&path, remaining)
            .with_context(|| format!("rewrite acknowledged claim {}", path.display()))
    }
}

fn read_journal_if_present(path: &Path) -> Result<Option<Vec<PendingEvent>>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read journal {}", path.display()));
        }
    };
    parse_journal(path, &bytes).map(Some)
}

fn parse_journal(path: &Path, bytes: &[u8]) -> Result<Vec<PendingEvent>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        anyhow::bail!(
            "self-dev journal {} has an incomplete final record; journal retained",
            path.display()
        );
    }
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("self-dev journal {} is not UTF-8", path.display()))?;
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            anyhow::bail!(
                "self-dev journal {} has an empty record at line {}; journal retained",
                path.display(),
                index + 1
            );
        }
        let mut event: PendingEvent = serde_json::from_str(line).with_context(|| {
            format!(
                "self-dev journal {} has a corrupt record at line {}; journal retained",
                path.display(),
                index + 1
            )
        })?;
        if event.audit_event_id.is_empty() {
            event.audit_event_id = derive_audit_event_id(&event);
        }
        validate_event(&event).with_context(|| {
            format!(
                "self-dev journal {} has an invalid record at line {}; journal retained",
                path.display(),
                index + 1
            )
        })?;
        events.push(event);
    }
    Ok(events)
}

fn validate_event(event: &PendingEvent) -> Result<()> {
    if event.proposal_id.is_empty()
        || event.proposal_id.len() > 128
        || !event
            .proposal_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        anyhow::bail!("proposal_id must be 1..=128 ASCII [a-zA-Z0-9_-]");
    }
    let expected_audit_event_id = derive_audit_event_id(event);
    if event.audit_event_id != expected_audit_event_id {
        anyhow::bail!("audit_event_id does not match the event's canonical content");
    }
    match event.kind {
        PendingKind::Proposed => {
            let proposal = event
                .proposal
                .as_ref()
                .context("proposed event is missing proposal payload")?;
            if proposal.id != event.proposal_id {
                anyhow::bail!("proposed event proposal_id does not match payload id");
            }
            if event.decline_reason.is_some() {
                anyhow::bail!("proposed event unexpectedly carries a decline reason");
            }
        }
        PendingKind::Accepted => {
            if event.proposal.is_some() || event.decline_reason.is_some() {
                anyhow::bail!("accepted event must not carry proposal or decline payload");
            }
        }
        PendingKind::Declined => {
            if event.proposal.is_some() {
                anyhow::bail!("declined event must not carry a proposal payload");
            }
            let reason = event
                .decline_reason
                .as_deref()
                .context("declined event is missing decline_reason")?;
            if reason.trim().is_empty() || reason.len() > 2_048 {
                anyhow::bail!("decline_reason must be non-empty and at most 2048 bytes");
            }
        }
    }
    Ok(())
}

fn derive_audit_event_id(event: &PendingEvent) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth:self-dev-outbox:audit-event:v1\0");
    digest.update([match event.kind {
        PendingKind::Proposed => 1,
        PendingKind::Accepted => 2,
        PendingKind::Declined => 3,
    }]);
    hash_len_prefixed(&mut digest, event.proposal_id.as_bytes());
    digest.update(event.ts_unix.to_le_bytes());
    match event.decline_reason.as_deref() {
        Some(reason) => {
            digest.update([1]);
            hash_len_prefixed(&mut digest, reason.as_bytes());
        }
        None => digest.update([0]),
    }
    hex::encode(digest.finalize())
}

fn hash_len_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

fn persist_journal(path: &Path, events: &[PendingEvent]) -> Result<()> {
    let mut bytes = Vec::new();
    for event in events {
        validate_event(event)?;
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    crate::util::atomic_write::atomic_write_private(path, &bytes)
        .with_context(|| format!("private atomic write {}", path.display()))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("fsync journal directory {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

async fn emit_event(writer: &WalWriterHandle, event: &PendingEvent) -> Result<()> {
    let (event_type, payload) = event_payload(event)?;
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    writer.append(header, payload).await?;
    Ok(())
}

fn event_payload(event: &PendingEvent) -> Result<(u8, Vec<u8>)> {
    match event.kind {
        PendingKind::Proposed => {
            let proposal = event
                .proposal
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("proposed event missing proposal payload"))?;
            let mut payload: serde_json::Value =
                serde_json::from_slice(&proposal.to_proposed_payload(event.ts_unix))
                    .context("decode canonical SELF_DEV_PROPOSED payload")?;
            payload
                .as_object_mut()
                .context("SELF_DEV_PROPOSED payload is not a JSON object")?
                .insert(
                    "audit_event_id".into(),
                    serde_json::Value::String(event.audit_event_id.clone()),
                );
            Ok((EVENT_TYPE_SELF_DEV_PROPOSED, serde_json::to_vec(&payload)?))
        }
        PendingKind::Accepted => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "audit_event_id": event.audit_event_id,
                "proposal_id": event.proposal_id,
                "ts_unix": event.ts_unix,
            }))
            .expect("SELF_DEV_ACCEPTED payload contains only infallible JSON values");
            Ok((EVENT_TYPE_SELF_DEV_ACCEPTED, payload))
        }
        PendingKind::Declined => {
            let reason = event
                .decline_reason
                .as_deref()
                .context("declined event missing decline_reason")?;
            let payload = serde_json::to_vec(&serde_json::json!({
                "audit_event_id": event.audit_event_id,
                "proposal_id": event.proposal_id,
                "reason": reason,
                "ts_unix": event.ts_unix,
            }))
            .expect("SELF_DEV_DECLINED payload contains only infallible JSON values");
            Ok((EVENT_TYPE_SELF_DEV_DECLINED, payload))
        }
    }
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
            extension_authority: None,
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

    #[test]
    fn audit_event_id_is_deterministic_content_bound_sha256() {
        let a = PendingEvent::declined("x", "timeout", 1_700_000_000);
        let same = PendingEvent::declined("x", "timeout", 1_700_000_000);
        let different_reason = PendingEvent::declined("x", "operator", 1_700_000_000);
        assert_eq!(a.audit_event_id, same.audit_event_id);
        assert_ne!(a.audit_event_id, different_reason.audit_event_id);
        assert_eq!(a.audit_event_id.len(), 64);
        assert!(
            a.audit_event_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
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
    async fn enqueue_deduplicates_pending_and_in_flight_by_audit_event_id() {
        let dir = tempdir().unwrap();
        let pending = PendingEvent::accepted("same", 1);
        enqueue(dir.path(), &pending).await.unwrap();
        enqueue(dir.path(), &pending).await.unwrap();
        assert_eq!(
            read_journal_if_present(&outbox_path(dir.path()))
                .unwrap()
                .unwrap()
                .len(),
            1
        );

        let claimed = read_journal_if_present(&outbox_path(dir.path()))
            .unwrap()
            .unwrap();
        persist_journal(&claim_path(dir.path()), &claimed).unwrap();
        crate::util::atomic_write::durable_remove_file(&outbox_path(dir.path())).unwrap();
        enqueue(dir.path(), &pending).await.unwrap();
        assert!(!outbox_path(dir.path()).exists());
    }

    #[test]
    fn legacy_record_gets_deterministic_audit_event_id_but_tampering_fails() {
        let event = PendingEvent::accepted("legacy", 7);
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().remove("audit_event_id");
        let mut legacy = serde_json::to_vec(&value).unwrap();
        legacy.push(b'\n');
        let parsed = parse_journal(Path::new("legacy.jsonl"), &legacy).unwrap();
        assert_eq!(parsed[0].audit_event_id, event.audit_event_id);

        let mut tampered = event;
        tampered.audit_event_id = "0".repeat(64);
        assert!(validate_event(&tampered).is_err());
    }

    #[test]
    fn every_wal_payload_carries_the_audit_event_id() {
        for event in [
            PendingEvent::proposed(fixture_proposal("proposed"), 1),
            PendingEvent::accepted("accepted", 2),
            PendingEvent::declined("declined", "no", 3),
        ] {
            let (_, payload) = event_payload(&event).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(
                value["audit_event_id"].as_str(),
                Some(event.audit_event_id.as_str())
            );
        }
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
    async fn drain_emits_then_removes_pending_and_claim() {
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
        assert!(!outbox_path(dir.path()).exists());
        assert!(!claim_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn corrupt_line_fails_loud_and_preserves_the_complete_journal() {
        let dir = tempdir().unwrap();
        let path = outbox_path(dir.path());
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let valid = serde_json::to_string(&PendingEvent::accepted("good", 1)).unwrap();
        let mix = format!("{valid}\nthis is not json\n{valid}\n");
        tokio::fs::write(&path, mix.as_bytes()).await.unwrap();
        let writer = test_writer().await;
        let error = drain_once(dir.path(), &writer).await.unwrap_err();
        assert!(error.to_string().contains("corrupt record at line 2"));
        assert_eq!(tokio::fs::read(&path).await.unwrap(), mix.as_bytes());
        assert!(!claim_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn concurrent_enqueues_are_lossless() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let mut tasks = Vec::new();
        for index in 0..24 {
            let task_home = home.clone();
            tasks.push(tokio::spawn(async move {
                enqueue(
                    &task_home,
                    &PendingEvent::accepted(format!("event-{index}"), index),
                )
                .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let events = read_journal_if_present(&outbox_path(&home))
            .unwrap()
            .unwrap();
        assert_eq!(events.len(), 24);
        let ids: std::collections::BTreeSet<_> =
            events.into_iter().map(|event| event.proposal_id).collect();
        assert_eq!(ids.len(), 24);
    }

    #[tokio::test]
    async fn later_emit_failure_acknowledges_prefix_and_retry_only_emits_suffix() {
        let dir = tempdir().unwrap();
        let first = PendingEvent::accepted("first", 1);
        let second = PendingEvent::accepted("second", 2);
        enqueue(dir.path(), &first).await.unwrap();
        enqueue(dir.path(), &second).await.unwrap();

        let first_payload_len = event_payload(&first).unwrap().1.len() as u64;
        let quota_home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let (limited_writer, limited_join) =
            crate::wal::writer::spawn(wal_dir.path().join("limited.wal"))
                .expect("spawn quota-limited writer");
        let limited_writer = limited_writer.with_quota_guard(std::sync::Arc::new(
            crate::wal::writer::QuotaGuard::new(quota_home.path().to_path_buf(), first_payload_len),
        ));

        let error = drain_once(dir.path(), &limited_writer).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("after 1 durable acknowledgement")
        );
        let retained = read_journal_if_present(&claim_path(dir.path()))
            .unwrap()
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].proposal_id, "second");
        assert!(!outbox_path(dir.path()).exists());

        drop(limited_writer);
        limited_join.await.unwrap();

        let retry_writer = test_writer().await;
        assert_eq!(drain_once(dir.path(), &retry_writer).await.unwrap(), 1);
        assert!(!claim_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn in_flight_claim_drains_before_new_pending_journal() {
        let dir = tempdir().unwrap();
        persist_journal(
            &claim_path(dir.path()),
            &[PendingEvent::accepted("claimed", 1)],
        )
        .unwrap();
        enqueue(dir.path(), &PendingEvent::accepted("new", 2))
            .await
            .unwrap();

        let writer = test_writer().await;
        assert_eq!(drain_once(dir.path(), &writer).await.unwrap(), 2);
        assert!(!claim_path(dir.path()).exists());
        assert!(!outbox_path(dir.path()).exists());
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
