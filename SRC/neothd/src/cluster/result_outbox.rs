//! Durable worker-side TaskResult delivery.
//!
//! A provider terminal outcome is first committed to the private membership
//! authority DB, then offered to the current exact authenticated session.  A
//! queue error, disconnect, or process restart leaves the immutable row
//! pending; reconnects replay the stored body and never invoke a provider.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;

use super::heartbeat::{
    FrameBody, FrameKind, TaskDelegateBody, TaskDelegateScope, TaskResultAckBody, TaskResultBody,
    WireFrame,
};
use super::membership::{
    MembershipGrant, MembershipStore, WorkerTaskExecutionReservation, WorkerTaskResultOutboxReceipt,
};
use super::peer_streams::{PeerStreamRegistry, SendError};

/// A healthy session gets a bounded retry at the existing heartbeat cadence
/// when the master never ACKs a queued frame (for example its custody commit
/// failed).  This is deliberately longer than a normal heartbeat to avoid
/// churn, and never starts another provider call.
pub const TASK_RESULT_ACK_RETRY_SECS: i64 = 15;

pub struct WorkerResultOutbox {
    store: MembershipStore,
    streams: Arc<PeerStreamRegistry>,
    local_peer_id: String,
    sequence: AtomicU64,
}

impl WorkerResultOutbox {
    pub fn new(
        home: &std::path::Path,
        streams: Arc<PeerStreamRegistry>,
        local_peer_id: String,
    ) -> Result<Self> {
        Ok(Self {
            store: MembershipStore::open(home)?,
            streams,
            local_peer_id,
            sequence: AtomicU64::new(0),
        })
    }

    pub fn persist_and_offer(
        &self,
        grant: &MembershipGrant,
        context_digest: &str,
        body: &TaskResultBody,
    ) -> Result<WorkerTaskResultOutboxReceipt> {
        let now = crate::time::now_unix_i64();
        let receipt =
            self.store
                .persist_worker_task_result_outbox(grant, context_digest, body, now)?;
        // A failed first offer is intentionally not an error: the durable row
        // is the completion boundary and a future authenticated reconnect will
        // resend it.  Do not expose completion text in a transport log.
        if self.offer(grant, body.clone()).is_ok() {
            let digest = super::heartbeat::task_result_digest(body)?;
            self.store
                .mark_worker_task_result_offered(grant, &body.task_id, &digest, now)?;
        }
        Ok(receipt)
    }

    pub fn reserve_delegate(
        &self,
        grant: &MembershipGrant,
        delegate: &TaskDelegateBody,
    ) -> Result<WorkerTaskExecutionReservation> {
        self.store.reserve_worker_task_execution(
            grant,
            &delegate.task_id,
            &delegate_context_digest(grant, delegate),
            crate::time::now_unix_i64(),
        )
    }

    pub fn replay_for_session(&self, grant: &MembershipGrant) -> Result<usize> {
        self.store
            .reset_offered_worker_task_results(grant, crate::time::now_unix_i64())?;
        self.flush_session(grant)
    }

    /// Drive only not-yet-offered rows into the current bounded session queue.
    /// A successful queue admission transitions the row to `offered`, so a
    /// later post-write flush advances the tail instead of endlessly replaying
    /// the same unacknowledged head. Reconnect resets offered rows to pending.
    pub fn flush_session(&self, grant: &MembershipGrant) -> Result<usize> {
        let pending = self
            .store
            .pending_worker_task_result_outbox(grant, crate::time::now_unix_i64())?;
        let mut offered = 0;
        for entry in pending {
            if self.offer(grant, entry.body.clone()).is_ok() {
                self.store.mark_worker_task_result_offered(
                    grant,
                    &entry.task_id,
                    &entry.result_digest,
                    crate::time::now_unix_i64(),
                )?;
                offered += 1;
            } else {
                // Queue/session failure is deliberately retained pending.  The
                // next session may offer again; it cannot reexecute work.
                break;
            }
        }
        Ok(offered)
    }

    pub fn retry_stale_for_session(&self, grant: &MembershipGrant, now_unix: i64) -> Result<usize> {
        let cutoff = now_unix.saturating_sub(TASK_RESULT_ACK_RETRY_SECS);
        self.store
            .reopen_stale_offered_worker_task_results(grant, cutoff, now_unix)?;
        self.flush_session(grant)
    }

    /// Duplicate TaskDelegate guard.  Retained acknowledged rows are terminal
    /// tombstones: they report `true` but are not resent.  Pending rows are
    /// offered again from durable custody, never recomputed.
    pub fn replay_duplicate_task(
        &self,
        grant: &MembershipGrant,
        delegate: &TaskDelegateBody,
    ) -> Result<bool> {
        let Some((entry, state)) = self.store.worker_task_result_outbox_for_task(
            grant,
            &delegate.task_id,
            crate::time::now_unix_i64(),
        )?
        else {
            return Ok(false);
        };
        anyhow::ensure!(
            entry.context_digest == delegate_context_digest(grant, delegate),
            "duplicate TaskDelegate conflicts with retained authenticated request context"
        );
        if state == "pending" && self.offer(grant, entry.body).is_ok() {
            let _ = self.store.mark_worker_task_result_offered(
                grant,
                &delegate.task_id,
                &entry.result_digest,
                crate::time::now_unix_i64(),
            );
        }
        Ok(true)
    }

    pub fn acknowledge(&self, grant: &MembershipGrant, ack: &TaskResultAckBody) -> Result<bool> {
        self.store
            .acknowledge_worker_task_result_outbox(grant, ack, crate::time::now_unix_i64())
    }

    fn offer(
        &self,
        grant: &MembershipGrant,
        body: TaskResultBody,
    ) -> std::result::Result<(), SendError> {
        let frame = WireFrame {
            kind: FrameKind::TaskResult,
            sequence: self
                .sequence
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1),
            sent_unix_ms: crate::time::now_unix_ms(),
            peer_id: self.local_peer_id.clone(),
            body: FrameBody::TaskResult(body),
        };
        self.streams
            .send_to(grant.transport_identity().as_str(), frame)
    }
}

pub fn delegate_context_digest(grant: &MembershipGrant, delegate: &TaskDelegateBody) -> String {
    delegate_context_digest_fields(
        grant.transport_identity().as_str(),
        &delegate.task_id,
        &delegate.prompt,
        delegate.model_hint.as_deref(),
        delegate.max_output_tokens,
        delegate.deadline_unix,
        delegate.scope.as_ref(),
    )
}

/// One exact context representation for reservation, rejection replay and the
/// normal executor result path. Keeping this independent of a concrete body
/// avoids a second almost-identical digest that can silently omit a new field.
pub fn delegate_context_digest_fields(
    transport_identity: &str,
    task_id: &str,
    prompt: &str,
    model_hint: Option<&str>,
    max_output_tokens: Option<u32>,
    deadline_unix: Option<i64>,
    scope: Option<&TaskDelegateScope>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"neoth.cluster.worker-task-result-context.v2\0");
    let scope = serde_json::to_vec(&scope).unwrap_or_default();
    let model_hint_value = model_hint.unwrap_or("");
    let ceiling = max_output_tokens.unwrap_or_default().to_be_bytes();
    let cap_present = [u8::from(max_output_tokens.is_some())];
    let hint_present = [u8::from(model_hint.is_some())];
    let deadline = deadline_unix.unwrap_or_default().to_be_bytes();
    let deadline_present = [u8::from(deadline_unix.is_some())];
    for value in [
        transport_identity.as_bytes(),
        task_id.as_bytes(),
        prompt.as_bytes(),
        model_hint_value.as_bytes(),
        scope.as_slice(),
        &ceiling,
        &cap_present,
        &hint_present,
        &deadline,
        &deadline_present,
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value);
    }
    hex::encode(digest.finalize())
}
