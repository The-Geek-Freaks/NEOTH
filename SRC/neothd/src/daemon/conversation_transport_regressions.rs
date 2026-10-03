//! A2 retained-owner regressions; these never open real audio.
#[cfg(test)]
mod tests {
    use crate::daemon::conversation_protocol as c;
    use crate::daemon::conversation_registry::{
        ConversationRegistry, ConversationRuntime, RetainedConversationOwner,
    };
    use crate::daemon::conversation_session::ConversationTaskRegistry;
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use uuid::Uuid;
    struct Owner {
        preflight: AtomicUsize,
        control: AtomicUsize,
    }
    fn event() -> c::ConversationEvent {
        c::ConversationEvent::State {
            state: c::ConversationState::Ready,
        }
    }
    #[async_trait]
    impl RetainedConversationOwner for Owner {
        async fn preflight(
            &self,
            _: c::ConversationPreflightRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            self.preflight.fetch_add(1, Ordering::SeqCst);
            Ok(event())
        }
        async fn decide_microphone(
            &self,
            _: c::ConversationMicrophoneDecisionRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            Ok(event())
        }
        async fn decide_provider(
            &self,
            _: c::ConversationProviderDecisionRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            Ok(event())
        }
        async fn start(
            &self,
            _: c::ConversationStartRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            Ok(event())
        }
        async fn abort_start(
            &self,
            _: c::ConversationAbortStartRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            Ok(event())
        }
        async fn control(
            &self,
            _: c::ConversationControlRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            self.control.fetch_add(1, Ordering::SeqCst);
            Ok(event())
        }
        async fn revoke_microphone(
            &self,
            _: c::ConversationRevokeMicrophoneRequest,
        ) -> c::ConversationResult<c::ConversationEvent> {
            Ok(event())
        }
        async fn close_and_drain(&self) -> c::ConversationResult<()> {
            Ok(())
        }
    }
    fn id() -> c::ConversationRequestId {
        c::ConversationRequestId(Uuid::new_v4())
    }
    async fn admitted() -> (
        ConversationRegistry,
        Arc<Owner>,
        c::ConversationProgressResponse,
    ) {
        let owner = Arc::new(Owner {
            preflight: AtomicUsize::new(0),
            control: AtomicUsize::new(0),
        });
        let registry = ConversationRegistry::new(
            "boot".into(),
            owner.clone(),
            ConversationTaskRegistry::default(),
        )
        .await
        .unwrap();
        let request = id();
        let reply = registry
            .preflight(c::ConversationPreflightRequest {
                schema_version: c::CONVERSATION_V1_SCHEMA_VERSION,
                expected_boot_id: "boot".into(),
                request_id: request,
                session_id: "session".into(),
                origin_surface: c::ConversationSurface::Buddy,
            })
            .await
            .unwrap();
        (registry, owner, reply)
    }
    #[tokio::test]
    async fn exact_preflight_replays_once_and_wrong_boot_has_no_effect() {
        let (registry, owner, first) = admitted().await;
        let retry = registry
            .preflight(c::ConversationPreflightRequest {
                schema_version: c::CONVERSATION_V1_SCHEMA_VERSION,
                expected_boot_id: "boot".into(),
                request_id: first.request_id,
                session_id: "session".into(),
                origin_surface: c::ConversationSurface::Buddy,
            })
            .await
            .unwrap();
        assert_eq!(owner.preflight.load(Ordering::SeqCst), 1);
        assert_eq!(first.subscription_id, retry.subscription_id);
        assert!(
            registry
                .preflight(c::ConversationPreflightRequest {
                    schema_version: c::CONVERSATION_V1_SCHEMA_VERSION,
                    expected_boot_id: "other".into(),
                    request_id: id(),
                    session_id: "session".into(),
                    origin_surface: c::ConversationSurface::Buddy
                })
                .await
                .is_err()
        );
        assert_eq!(owner.preflight.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn foreign_request_or_generation_has_no_control_effect() {
        let (registry, owner, reply) = admitted().await;
        let subscription = reply.subscription_id.unwrap();
        assert!(
            registry
                .control(c::ConversationControlRequest {
                    schema_version: c::CONVERSATION_V1_SCHEMA_VERSION,
                    expected_boot_id: "boot".into(),
                    request_id: id(),
                    subscription_id: subscription.clone(),
                    session_id: "session".into(),
                    origin_surface: c::ConversationSurface::Buddy,
                    expected_generation: reply.generation,
                    control: c::ConversationControl::Stop
                })
                .await
                .is_err()
        );
        assert!(
            registry
                .control(c::ConversationControlRequest {
                    schema_version: c::CONVERSATION_V1_SCHEMA_VERSION,
                    expected_boot_id: "boot".into(),
                    request_id: reply.request_id,
                    subscription_id: subscription,
                    session_id: "session".into(),
                    origin_surface: c::ConversationSurface::Buddy,
                    expected_generation: reply.generation + 1,
                    control: c::ConversationControl::Stop
                })
                .await
                .is_err()
        );
        assert_eq!(owner.control.load(Ordering::SeqCst), 0);
    }
}
