//! Crate-private A2 junction proposed for `daemon/mod.rs`.
//!
//! The actual owner is `media::conversation_loop::ConversationSession`; this
//! narrow daemon module is retained so the GUI can later supply only sealed
//! microphone/provider decisions and never direct provider or device handles.
//! It also owns every dropped text-turn settlement task.  The stream adapter
//! receives this registry, never the GUI runtime's private task set and never a
//! loose `tokio::spawn` capability.

#[cfg(any(test, feature = "live-audio"))]
use std::future::Future;
#[cfg(any(test, feature = "live-audio"))]
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

// The registry is also the stream/WAL settlement owner in default builds.
// Only the live-media facade itself is feature-gated by Root's daemon module
// registration, avoiding a default-build dependency on conversation_loop.
#[cfg(feature = "live-audio")]
pub(crate) use crate::media::conversation_loop::{ConversationEvent, ConversationSession, ConversationStart};

#[cfg(any(test, feature = "live-audio"))]
pub(crate) type ConversationCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Clone, Default)]
pub(crate) struct ConversationTaskRegistry {
    cleanup: Arc<Mutex<JoinSet<()>>>,
    stages: Arc<Mutex<JoinSet<Result<(), &'static str>>>>,
}

impl ConversationTaskRegistry {
    /// Registration is bounded by the stream supervisor's single-active-turn
    /// invariant.  The registry lives in the daemon session root and is drained
    /// before microphone/WAL teardown, so a dropped consumer cannot outlive it.
    #[cfg(any(test, feature = "live-audio"))]
    pub(crate) async fn spawn_cleanup(
        &self,
        task: ConversationCleanupFuture,
    ) -> Result<(), &'static str> {
        self.cleanup.lock().await.spawn(task);
        Ok(())
    }

    /// Functional A2 stages remain in this registry until the owner observes
    /// their completion through `settle_one_stage`.  Unlike the prior
    /// one-shot projection, no result receiver can be dropped by the caller.
    #[cfg(any(test, feature = "live-audio"))]
    pub(crate) async fn spawn_stage<F>(&self, stage: F) -> Result<(), &'static str>
    where
        F: Future<Output = Result<(), &'static str>> + Send + 'static,
    {
        self.stages.lock().await.spawn(stage);
        Ok(())
    }

    /// Await exactly one retained functional stage.  The A2 loop is its sole
    /// registrar and consumer, so the mutex deliberately protects a coherent
    /// JoinSet ownership transition; losing `select!` branches are dropped.
    #[cfg(any(test, feature = "live-audio"))]
    pub(crate) async fn settle_one_stage(&self) -> Result<(), &'static str> {
        let mut stages = self.stages.lock().await;
        match stages.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err("conversation_stage_worker_panicked"),
            None => Err("conversation_stage_registry_empty"),
        }
    }

    /// Drain functional work before asking an owner cleanup worker to stop.
    /// This ordering lets a cancelled visible turn publish or durably retain
    /// its real terminal settlement; it is never inferred from task abortion.
    pub(crate) async fn drain_stages(&self) -> Result<(), &'static str> {
        let mut first_error = None;
        let mut stages = self.stages.lock().await;
        while let Some(next) = stages.join_next().await {
            match next {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Ok(Err(_)) => {}
                Err(_) if first_error.is_none() => first_error = Some("conversation_stage_worker_panicked"),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Cleanup is drained only after its clients have settled and requested
    /// shutdown.  Keep joining after the first fault so no retained worker is
    /// silently left running.
    pub(crate) async fn drain_cleanup(&self) -> Result<(), &'static str> {
        let mut first_error = None;
        let mut tasks = self.cleanup.lock().await;
        while let Some(next) = tasks.join_next().await {
            match next {
                Ok(()) => {}
                Err(_) if first_error.is_none() => first_error = Some("authorized_text_turn_cleanup_task_failed"),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(crate) async fn drain(&self) -> Result<(), &'static str> {
        let stages = self.drain_stages().await;
        let cleanup = self.drain_cleanup().await;
        stages.and(cleanup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retained_stage_failure_reaches_the_session_owner() {
        let registry = ConversationTaskRegistry::default();
        registry.spawn_stage(async { Err("stt_stage_failed") }).await.unwrap();
        assert_eq!(registry.settle_one_stage().await, Err("stt_stage_failed"));
    }

    #[tokio::test]
    async fn retained_stage_reports_closed_bounded_result_queue() {
        let registry = ConversationTaskRegistry::default();
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        drop(rx);
        registry.spawn_stage(async move {
            tx.send(()).await.map_err(|_| "a2_stage_queue_closed")
        }).await.unwrap();
        assert_eq!(registry.settle_one_stage().await, Err("a2_stage_queue_closed"));
    }

    #[tokio::test]
    async fn drain_stages_joins_a_later_blocked_worker_after_the_first_failure() {
        let registry = ConversationTaskRegistry::default();
        let (release, hold) = tokio::sync::oneshot::channel::<()>();
        registry.spawn_stage(async { Err("first_stage_failed") }).await.unwrap();
        registry.spawn_stage(async move {
            hold.await.map_err(|_| "blocked_stage_release_lost")?;
            Ok(())
        }).await.unwrap();
        let joining = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.drain_stages().await })
        };
        tokio::task::yield_now().await;
        release.send(()).unwrap();
        assert_eq!(joining.await.unwrap(), Err("first_stage_failed"));
        assert_eq!(registry.drain_stages().await, Ok(()));
    }
}
