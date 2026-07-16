//! Bounded live integration-job events backed by durable SQLite snapshots.
//!
//! The broadcast channel is notification-only. A lagged/restarted consumer
//! resynchronises from [`IntegrationJobSubscription::snapshot`] (or the job
//! service's `snapshot` method). The subscription accepts only contiguous,
//! strictly increasing per-job revisions and requires a new snapshot after a
//! gap. This is the same subscribe-before-snapshot contract used by the daemon
//! SSE feeds and never treats an in-memory event as durable.

use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::state::{IntegrationJob, JobId, JobState};

pub const DEFAULT_JOB_EVENT_CAPACITY: usize = 256;

#[cfg(test)]
type BeforePublishHook = Arc<dyn Fn(&IntegrationJobEvent) + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntegrationJobEventKind {
    Created,
    StateChanged { previous: JobState },
    Progress,
    CancellationRequested,
    Retried { retry_of: JobId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationJobEvent {
    pub event: IntegrationJobEventKind,
    pub job: IntegrationJob,
}

/// Race-free subscription bootstrap.
///
/// The receiver is created before the durable snapshot is read. Events whose
/// revision is already represented in `snapshot` may therefore be duplicated,
/// but no committed revision can be missed.
pub struct IntegrationJobSubscription {
    pub snapshot: Vec<IntegrationJob>,
    receiver: broadcast::Receiver<IntegrationJobEvent>,
    revisions: BTreeMap<JobId, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntegrationJobReceiveError {
    #[error("no integration job event is currently available")]
    Empty,
    #[error("integration job event stream closed")]
    Closed,
    #[error("integration job event stream requires a fresh durable snapshot")]
    ResyncRequired,
}

impl IntegrationJobSubscription {
    pub(crate) fn new(
        snapshot: Vec<IntegrationJob>,
        receiver: broadcast::Receiver<IntegrationJobEvent>,
    ) -> Self {
        let revisions = snapshot
            .iter()
            .map(|job| (job.job_id.clone(), job.state_revision))
            .collect();
        Self {
            snapshot,
            receiver,
            revisions,
        }
    }

    pub async fn recv(&mut self) -> Result<IntegrationJobEvent, IntegrationJobReceiveError> {
        loop {
            let event = self.receiver.recv().await.map_err(|error| match error {
                broadcast::error::RecvError::Closed => IntegrationJobReceiveError::Closed,
                broadcast::error::RecvError::Lagged(_) => {
                    IntegrationJobReceiveError::ResyncRequired
                }
            })?;
            if let Some(event) = self.accept_monotone(event)? {
                return Ok(event);
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<IntegrationJobEvent, IntegrationJobReceiveError> {
        loop {
            let event = self.receiver.try_recv().map_err(|error| match error {
                broadcast::error::TryRecvError::Empty => IntegrationJobReceiveError::Empty,
                broadcast::error::TryRecvError::Closed => IntegrationJobReceiveError::Closed,
                broadcast::error::TryRecvError::Lagged(_) => {
                    IntegrationJobReceiveError::ResyncRequired
                }
            })?;
            if let Some(event) = self.accept_monotone(event)? {
                return Ok(event);
            }
        }
    }

    fn accept_monotone(
        &mut self,
        event: IntegrationJobEvent,
    ) -> Result<Option<IntegrationJobEvent>, IntegrationJobReceiveError> {
        let revision = event.job.state_revision;
        match self.revisions.get(&event.job.job_id).copied() {
            Some(previous) if revision <= previous => return Ok(None),
            Some(previous) if revision != previous + 1 => {
                return Err(IntegrationJobReceiveError::ResyncRequired);
            }
            None if revision != 0
                || !matches!(
                    &event.event,
                    IntegrationJobEventKind::Created | IntegrationJobEventKind::Retried { .. }
                ) =>
            {
                return Err(IntegrationJobReceiveError::ResyncRequired);
            }
            _ => {}
        }
        self.revisions.insert(event.job.job_id.clone(), revision);
        Ok(Some(event))
    }
}

#[derive(Clone)]
pub(crate) struct IntegrationJobEventBus {
    sender: broadcast::Sender<IntegrationJobEvent>,
    #[cfg(test)]
    before_publish: Option<BeforePublishHook>,
}

impl IntegrationJobEventBus {
    pub(crate) fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            sender,
            #[cfg(test)]
            before_publish: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_before_publish(mut self, hook: BeforePublishHook) -> Self {
        self.before_publish = Some(hook);
        self
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<IntegrationJobEvent> {
        self.sender.subscribe()
    }

    pub(crate) fn publish(&self, event: IntegrationJobEvent) {
        #[cfg(test)]
        if let Some(hook) = &self.before_publish {
            hook(&event);
        }
        // Zero live subscribers is normal; durable state was committed first.
        let _ = self.sender.send(event);
    }
}
