//! Daemon-local A2 adapter from the retained GUI-chat runtime to the sealed
//! visible-text turn interface.  It performs no audit-RPC, listener, raw
//! request decoding, provider construction, or microphone work.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::daemon::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeDecisionOutcome, GuiChatBridgeDecisionReceipt, GuiChatBridgeError,
    GuiChatBridgeEventSink, GuiChatBridgePreflight, GuiChatBridgePreflightInput,
    GuiChatBridgePreflightReceipt, GuiChatBridgeResult, GuiChatBridgeSubscription,
    GuiChatBridgeTurn, GuiChatConsentDecision, GuiChatConsentPrompt, GuiChatConsentRoute,
    GuiChatPhase, GuiChatSubscriptionMetadata, GuiChatSurface, GuiChatTurnId, GuiChatTurnMetadata,
};
use crate::daemon::gui_chat_protocol as protocol;
use crate::daemon::gui_chat_protocol::{GuiChatFrameSink, GuiChatRuntime};

pub(crate) struct DirectConversationGuiChatBridge {
    runtime: Arc<dyn GuiChatRuntime>,
    home: PathBuf,
    boot_id: String,
    active: Mutex<Option<ActiveGrant>>,
}

struct ActiveGrant {
    origin_surface: GuiChatSurface,
    session_id: String,
    grant: protocol::GuiChatOpaqueCapability,
    start: protocol::GuiChatStartResponse,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PreflightSealed {
    request: protocol::GuiChatPreflightRequest,
    response: protocol::GuiChatPreflightResponse,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DecisionSealed {
    request: protocol::GuiChatPreflightRequest,
    turn_intent_digest: protocol::GuiChatDigest,
    start_capability: protocol::GuiChatOpaqueCapability,
    attachment_tickets: Vec<protocol::GuiChatAttachmentTicket>,
}

impl DirectConversationGuiChatBridge {
    pub(crate) fn new(runtime: Arc<dyn GuiChatRuntime>, home: PathBuf, boot_id: String) -> Self {
        Self {
            runtime,
            home,
            boot_id,
            active: Mutex::new(None),
        }
    }

    fn require_boot(&self, boot_id: &str) -> GuiChatBridgeResult<()> {
        if boot_id == self.boot_id {
            Ok(())
        } else {
            Err(error("daemon boot changed"))
        }
    }
}

#[async_trait]
impl GuiChatBridge for DirectConversationGuiChatBridge {
    async fn preflight(
        &self,
        input: GuiChatBridgePreflightInput,
    ) -> GuiChatBridgeResult<GuiChatBridgePreflight> {
        let request = protocol::GuiChatPreflightRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            request_id: protocol::GuiChatRequestId(input.request_id.as_uuid()),
            session_id: input.session_id,
            surface_account_id: None,
            origin_surface: surface(input.origin_surface),
            message: input.message,
            model: input.model,
            skill_id: input.skill_id,
            incognito: input.incognito,
            reasoning_display: input.reasoning_display,
            attachments: input
                .attachment_paths
                .into_iter()
                .map(|path| protocol::GuiChatAttachmentCandidate {
                    path: path.to_string_lossy().into_owned(),
                })
                .collect(),
        };
        protocol::validate_preflight_request(&request)
            .map_err(|_| GuiChatBridgeError::invalid("preflight"))?;
        let response = runtime_result(self.runtime.preflight(request.clone()).await)?;
        protocol::validate_preflight_response(&response)
            .map_err(|_| error("invalid preflight response"))?;
        self.require_boot(&response.expected_boot_id)?;
        match response.consent.clone() {
            protocol::GuiChatConsentPreflightState::Ready => {
                let proof =
                    crate::cli::consent_challenge::mint_ready_request_bound_gui_chat_consent(
                        &self.home,
                        &response.preflight_descriptor_digest.0,
                        &response.consent_challenge.0,
                        &request.session_id,
                        crate::time::now_unix_secs(),
                    )
                    .map_err(|_| error("ready existing-grant verification failed"))?;
                let decide = protocol::GuiChatConsentDecisionRequest {
                    schema_version: 1,
                    expected_boot_id: self.boot_id.clone(),
                    preflight_id: response.preflight_id.clone(),
                    preflight_descriptor_digest: response.preflight_descriptor_digest.clone(),
                    consent_challenge: response.consent_challenge.clone(),
                    decision: protocol::GuiChatConsentDecision::AllowOnce,
                    consent_proof: Some(protocol::GuiChatConsentProof(proof.to_string())),
                };
                protocol::validate_decide_request(&decide)
                    .map_err(|_| error("invalid ready proof"))?;
                let reply = runtime_result(self.runtime.decide(decide).await)?;
                protocol::validate_decide_response(&reply)
                    .map_err(|_| error("invalid ready decision response"))?;
                let sealed = approved(request, reply, &self.boot_id)?;
                Ok(GuiChatBridgePreflight::Ready {
                    decision: GuiChatBridgeDecisionReceipt::from_live(seal(&sealed)?),
                })
            }
            protocol::GuiChatConsentPreflightState::ConfirmationRequired { prompt } => {
                if prompt.request_id != request.request_id {
                    return Err(error("consent prompt request binding mismatch"));
                }
                Ok(GuiChatBridgePreflight::ConfirmationRequired {
                    receipt: GuiChatBridgePreflightReceipt::from_live(seal(&PreflightSealed {
                        request,
                        response,
                    })?),
                    prompt: GuiChatConsentPrompt {
                        request_id: input.request_id,
                        routes: prompt
                            .routes
                            .into_iter()
                            .map(|route| GuiChatConsentRoute {
                                provider: route.provider,
                                endpoint_origin: route.endpoint_origin,
                            })
                            .collect(),
                        expires_at_unix_ms: prompt.expires_at_unix_ms,
                    },
                })
            }
        }
    }

    async fn decide(
        &self,
        preflight: GuiChatBridgePreflightReceipt,
        decision: GuiChatConsentDecision,
    ) -> GuiChatBridgeResult<GuiChatBridgeDecisionOutcome> {
        let sealed: PreflightSealed = unseal(preflight.sealed_bytes_for_daemon()?)?;
        self.require_boot(&sealed.request.expected_boot_id)?;
        let proof = match decision {
            GuiChatConsentDecision::Deny => None,
            GuiChatConsentDecision::AllowOnce | GuiChatConsentDecision::AllowAlways => {
                crate::cli::consent_challenge::decide_request_bound_gui_chat_consent(
                    &self.home,
                    &sealed.response.consent_challenge.0,
                    &sealed.response.preflight_descriptor_digest.0,
                    &sealed.request.session_id,
                    match decision {
                        GuiChatConsentDecision::AllowOnce => {
                            crate::cli::consent_challenge::ChatConsentDecision::AllowOnce
                        }
                        GuiChatConsentDecision::AllowAlways => {
                            crate::cli::consent_challenge::ChatConsentDecision::AllowAlways
                        }
                        GuiChatConsentDecision::Deny => unreachable!(),
                    },
                )
                .await
                .map_err(|_| error("verified local consent unavailable"))?
                .map(|proof| protocol::GuiChatConsentProof(proof.to_string()))
            }
        };
        let request = protocol::GuiChatConsentDecisionRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            preflight_id: sealed.response.preflight_id,
            preflight_descriptor_digest: sealed.response.preflight_descriptor_digest,
            consent_challenge: sealed.response.consent_challenge,
            decision: self::decision(decision),
            consent_proof: proof,
        };
        protocol::validate_decide_request(&request)
            .map_err(|_| error("invalid core consent proof"))?;
        let response = runtime_result(self.runtime.decide(request).await)?;
        protocol::validate_decide_response(&response)
            .map_err(|_| error("invalid consent response"))?;
        match response {
            protocol::GuiChatConsentDecisionResponse::Denied {
                expected_boot_id, ..
            } => {
                self.require_boot(&expected_boot_id)?;
                Ok(GuiChatBridgeDecisionOutcome::Denied)
            }
            approved_response @ protocol::GuiChatConsentDecisionResponse::Approved {
                ref expected_boot_id,
                ..
            } => {
                self.require_boot(expected_boot_id)?;
                Ok(GuiChatBridgeDecisionOutcome::Approved(
                    GuiChatBridgeDecisionReceipt::from_live(seal(&approved(
                        sealed.request,
                        approved_response,
                        &self.boot_id,
                    )?)?),
                ))
            }
        }
    }

    async fn start(
        &self,
        decision_receipt: GuiChatBridgeDecisionReceipt,
    ) -> GuiChatBridgeResult<GuiChatBridgeTurn> {
        let sealed: DecisionSealed = unseal(decision_receipt.sealed_bytes_for_daemon()?)?;
        self.require_boot(&sealed.request.expected_boot_id)?;
        let request = protocol::GuiChatStartRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            request_id: sealed.request.request_id,
            session_id: sealed.request.session_id.clone(),
            origin_surface: sealed.request.origin_surface,
            turn_intent_digest: sealed.turn_intent_digest,
            start_capability: sealed.start_capability,
            attachment_tickets: sealed.attachment_tickets,
        };
        protocol::validate_start_request(&request).map_err(|_| error("invalid start receipt"))?;
        let response = runtime_result(self.runtime.start(request).await)?;
        protocol::validate_start_response(&response)
            .map_err(|_| error("invalid start response"))?;
        self.require_boot(&response.expected_boot_id)?;
        let origin_surface = input_surface(sealed.request.origin_surface)?;
        self.active
            .lock()
            .map_err(|_| error("GUI bridge state poisoned"))?
            .replace(ActiveGrant {
                origin_surface,
                session_id: sealed.request.session_id,
                grant: response.same_session_attach_grant.grant.clone(),
                start: response.clone(),
            });
        Ok(GuiChatBridgeTurn::from_live(
            GuiChatTurnMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(response.turn_id.0),
                origin_surface,
                phase: GuiChatPhase::Waiting,
                latest_sequence: response.initial_sequence,
            },
            seal(&response)?,
        ))
    }

    async fn active(&self) -> GuiChatBridgeResult<Option<GuiChatBridgeTurn>> {
        let Some((origin_surface, session_id, grant, start)) = self
            .active
            .lock()
            .map_err(|_| error("GUI bridge state poisoned"))?
            .as_ref()
            .map(|value| {
                (
                    value.origin_surface,
                    value.session_id.clone(),
                    value.grant.clone(),
                    value.start.clone(),
                )
            })
        else {
            return Ok(None);
        };
        let response = runtime_result(
            self.runtime
                .active(protocol::GuiChatActiveRequest {
                    schema_version: 1,
                    expected_boot_id: self.boot_id.clone(),
                    session_id,
                    same_session_attach_grant: grant,
                })
                .await,
        )?;
        protocol::validate_active_response(&response)
            .map_err(|_| error("invalid active response"))?;
        self.require_boot(&response.expected_boot_id)?;
        let Some(turn) = response.active_turn else {
            self.active
                .lock()
                .map_err(|_| error("GUI bridge state poisoned"))?
                .take();
            return Ok(None);
        };
        Ok(Some(GuiChatBridgeTurn::from_live(
            GuiChatTurnMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(turn.turn_id.0),
                origin_surface,
                phase: phase(turn.phase),
                latest_sequence: turn.latest_sequence,
            },
            seal(&start)?,
        )))
    }

    async fn exchange_same_session_attach(
        &self,
        turn: &GuiChatBridgeTurn,
        requested_surface: GuiChatSurface,
    ) -> GuiChatBridgeResult<GuiChatBridgeSubscription> {
        self.require_boot(&turn.metadata.boot_id)?;
        let start: protocol::GuiChatStartResponse = unseal(turn.sealed_bytes_for_daemon()?)?;
        let request = protocol::GuiChatAttachExchangeRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: start.turn_id,
            session_id: start.same_session_attach_grant.session_id.clone(),
            desired_surface: surface(requested_surface),
            grant: start.same_session_attach_grant.grant,
        };
        protocol::validate_attach_exchange_request(&request)
            .map_err(|_| error("invalid attach exchange receipt"))?;
        let response = runtime_result(self.runtime.exchange_attach(request).await)?;
        protocol::validate_attach_exchange_response(&response)
            .map_err(|_| error("invalid attach exchange response"))?;
        self.require_boot(&response.expected_boot_id)?;
        if response.surface != surface(requested_surface) {
            return Err(error("attach exchange binding mismatch"));
        }
        Ok(GuiChatBridgeSubscription::from_live(
            GuiChatSubscriptionMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(response.turn_id.0),
                surface: requested_surface,
                generation: response.subscription_generation,
                latest_sequence: response.initial_sequence,
            },
            seal(&response)?,
        ))
    }

    async fn attach(
        &self,
        subscription: GuiChatBridgeSubscription,
        after_sequence: u64,
        sink: &mut dyn GuiChatBridgeEventSink,
    ) -> GuiChatBridgeResult<()> {
        self.require_boot(&subscription.metadata.boot_id)?;
        let sealed: protocol::GuiChatAttachExchangeResponse =
            unseal(subscription.sealed_bytes_for_daemon()?)?;
        let expected_session_id = sealed.session_id.clone();
        let request = protocol::GuiChatAttachRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: sealed.turn_id,
            session_id: sealed.session_id,
            surface: sealed.surface,
            subscription_generation: sealed.subscription_generation,
            attach_capability: sealed.attach_capability,
            after_sequence,
        };
        let mut frame_sink = DirectFrameSink {
            metadata: subscription.metadata.clone(),
            expected_session_id,
            sink,
        };
        runtime_result(self.runtime.attach_frames(request, &mut frame_sink).await)?;
        Ok(())
    }

    async fn cancel(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<()> {
        self.require_boot(&turn.metadata.boot_id)?;
        let start: protocol::GuiChatStartResponse = unseal(turn.sealed_bytes_for_daemon()?)?;
        let response = runtime_result(
            self.runtime
                .cancel(protocol::GuiChatCancelRequest {
                    schema_version: 1,
                    expected_boot_id: self.boot_id.clone(),
                    turn_id: start.turn_id,
                    session_id: start.same_session_attach_grant.session_id,
                    cancel_capability: start.cancel_capability,
                })
                .await,
        )?;
        if response.schema_version != 1 {
            return Err(error("invalid cancel response"));
        }
        Ok(())
    }

    async fn status(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<GuiChatTurnMetadata> {
        self.require_boot(&turn.metadata.boot_id)?;
        let start: protocol::GuiChatStartResponse = unseal(turn.sealed_bytes_for_daemon()?)?;
        let response = runtime_result(
            self.runtime
                .status(protocol::GuiChatStatusRequest {
                    schema_version: 1,
                    expected_boot_id: self.boot_id.clone(),
                    turn_id: start.turn_id,
                    session_id: start.same_session_attach_grant.session_id,
                    attach_capability: start.origin_attach_capability,
                })
                .await,
        )?;
        protocol::validate_status_response(&response)
            .map_err(|_| error("invalid status response"))?;
        self.require_boot(&response.expected_boot_id)?;
        Ok(GuiChatTurnMetadata {
            boot_id: self.boot_id.clone(),
            turn_id: GuiChatTurnId(response.turn_id.0),
            origin_surface: turn.metadata.origin_surface,
            phase: phase(response.phase),
            latest_sequence: response.latest_sequence,
        })
    }
}

struct DirectFrameSink<'a> {
    metadata: GuiChatSubscriptionMetadata,
    expected_session_id: String,
    sink: &'a mut dyn GuiChatBridgeEventSink,
}
impl GuiChatFrameSink for DirectFrameSink<'_> {
    fn on_frame(&mut self, frame: protocol::GuiChatStreamFrame) -> protocol::GuiChatResult<()> {
        if frame.boot_id != self.metadata.boot_id
            || frame.turn_id.0 != self.metadata.turn_id.as_uuid()
            || frame.subscription.session_id != self.expected_session_id
            || frame.subscription.surface != surface(self.metadata.surface)
            || frame.subscription.generation != self.metadata.generation
        {
            return Err(protocol::GuiChatProtocolError::Invalid(
                "direct_frame_binding",
            ));
        }
        self.sink
            .on_event(crate::daemon::gui_chat_bridge::map_frame_for_daemon(
                frame,
                self.metadata.clone(),
            ))
            .map_err(|_| protocol::GuiChatProtocolError::Invalid("direct_frame_sink"))
    }
}

fn error(detail: &'static str) -> GuiChatBridgeError {
    GuiChatBridgeError::unavailable_for_daemon(detail)
}
fn runtime_result<T>(value: protocol::GuiChatResult<T>) -> GuiChatBridgeResult<T> {
    value.map_err(|_| error("GUI chat runtime rejected request"))
}
fn seal<T: serde::Serialize>(value: &T) -> GuiChatBridgeResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| error("seal GUI bridge receipt"))
}
fn unseal<T: serde::de::DeserializeOwned>(value: &[u8]) -> GuiChatBridgeResult<T> {
    serde_json::from_slice(value).map_err(|_| error("invalid sealed GUI bridge receipt"))
}
fn decision(value: GuiChatConsentDecision) -> protocol::GuiChatConsentDecision {
    match value {
        GuiChatConsentDecision::Deny => protocol::GuiChatConsentDecision::Deny,
        GuiChatConsentDecision::AllowOnce => protocol::GuiChatConsentDecision::AllowOnce,
        GuiChatConsentDecision::AllowAlways => protocol::GuiChatConsentDecision::AllowAlways,
    }
}
fn surface(value: GuiChatSurface) -> protocol::GuiChatSurface {
    match value {
        GuiChatSurface::Main => protocol::GuiChatSurface::Main,
        GuiChatSurface::Buddy => protocol::GuiChatSurface::Buddy,
    }
}
fn input_surface(value: protocol::GuiChatSurface) -> GuiChatBridgeResult<GuiChatSurface> {
    match value {
        protocol::GuiChatSurface::Main => Ok(GuiChatSurface::Main),
        protocol::GuiChatSurface::Buddy => Ok(GuiChatSurface::Buddy),
        protocol::GuiChatSurface::WebChat => Err(error(
            "webchat surface is unavailable to the native GUI bridge",
        )),
    }
}
fn phase(value: protocol::GuiChatPhase) -> GuiChatPhase {
    match value {
        protocol::GuiChatPhase::Waiting => GuiChatPhase::Waiting,
        protocol::GuiChatPhase::Receiving => GuiChatPhase::Receiving,
        protocol::GuiChatPhase::Finalizing => GuiChatPhase::Finalizing,
    }
}
fn approved(
    request: protocol::GuiChatPreflightRequest,
    response: protocol::GuiChatConsentDecisionResponse,
    boot_id: &str,
) -> GuiChatBridgeResult<DecisionSealed> {
    match response {
        protocol::GuiChatConsentDecisionResponse::Approved {
            expected_boot_id,
            turn_intent_digest,
            start_capability,
            attachment_tickets,
            ..
        } if expected_boot_id == boot_id => Ok(DecisionSealed {
            request,
            turn_intent_digest,
            start_capability,
            attachment_tickets,
        }),
        protocol::GuiChatConsentDecisionResponse::Approved { .. } => {
            Err(error("daemon boot changed during consent"))
        }
        protocol::GuiChatConsentDecisionResponse::Denied { .. } => {
            Err(error("consent decision denied"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingSink;
    impl GuiChatBridgeEventSink for RecordingSink {
        fn on_event(
            &mut self,
            _event: crate::daemon::gui_chat_bridge::GuiChatBridgeEvent,
        ) -> GuiChatBridgeResult<()> {
            Ok(())
        }
    }

    #[test]
    fn direct_frame_rejects_wrong_session_before_gui_projection() {
        let turn = uuid::Uuid::now_v7();
        let metadata = GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id: GuiChatTurnId(turn),
            surface: GuiChatSurface::Buddy,
            generation: 7,
            latest_sequence: 0,
        };
        let mut recording = RecordingSink;
        let mut sink = DirectFrameSink {
            metadata,
            expected_session_id: "owned-session".into(),
            sink: &mut recording,
        };
        let rejected = sink.on_frame(protocol::GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot-a".into(),
            turn_id: protocol::GuiChatTurnId(turn),
            subscription: protocol::GuiChatSubscription {
                session_id: "foreign-session".into(),
                surface: protocol::GuiChatSurface::Buddy,
                generation: 7,
            },
            sequence: 1,
            payload: protocol::GuiChatFramePayload::CancelRequested,
        });
        assert!(matches!(
            rejected,
            Err(protocol::GuiChatProtocolError::Invalid(
                "direct_frame_binding"
            ))
        ));
    }

    #[test]
    fn direct_frame_rejects_stale_subscription_generation_before_gui_projection() {
        let turn = uuid::Uuid::now_v7();
        let metadata = GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id: GuiChatTurnId(turn),
            surface: GuiChatSurface::Buddy,
            generation: 7,
            latest_sequence: 0,
        };
        let mut recording = RecordingSink;
        let mut sink = DirectFrameSink {
            metadata,
            expected_session_id: "owned-session".into(),
            sink: &mut recording,
        };
        let rejected = sink.on_frame(protocol::GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot-a".into(),
            turn_id: protocol::GuiChatTurnId(turn),
            subscription: protocol::GuiChatSubscription {
                session_id: "owned-session".into(),
                surface: protocol::GuiChatSurface::Buddy,
                generation: 6,
            },
            sequence: 1,
            payload: protocol::GuiChatFramePayload::CancelRequested,
        });
        assert!(matches!(
            rejected,
            Err(protocol::GuiChatProtocolError::Invalid(
                "direct_frame_binding"
            ))
        ));
    }
}
