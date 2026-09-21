//! Separate-crate facade and reducer-fixture test. Alongside facade values it
//! imports only non-authorizing reasoning text/state values, never an audit
//! stream, engine event, provider capability, wire DTO, credential, or proof.

use neothd::daemon::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeEvent, GuiChatBridgePreflight, GuiChatBridgePreflightInput,
    GuiChatBridgeRecallChipBatch, GuiChatBridgeRecallChipRow, GuiChatBridgeRecallChipSourceState,
    GuiChatBridgeRecallChipStatus, GuiChatBridgeRecallChipTier,
    GuiChatBridgeResponseFeedbackTarget, GuiChatBridgeThroughputBasis,
    GuiChatBridgeThroughputState, GuiChatConsentDecision, GuiChatConsentPrompt,
    GuiChatConsentRoute, GuiChatPhase, GuiChatSubscriptionMetadata, GuiChatSurface,
    GuiChatTerminalState, GuiChatTurnMetadata, gui_bridge_test_support,
};
use neothd::providers::{ReasoningTerminalState, ReasoningText};

fn accepts_public_bridge(_: &dyn GuiChatBridge) {}

#[test]
fn gui_crate_has_non_authorizing_reducer_fixtures_and_explicit_consent_types() {
    let input = GuiChatBridgePreflightInput {
        request_id: neothd::daemon::gui_chat_bridge::GuiChatRequestId::new(),
        session_id: "same-session".into(),
        origin_surface: GuiChatSurface::Buddy,
        message: "hello".into(),
        model: None,
        skill_id: None,
        incognito: false,
        reasoning_display: false,
        attachment_paths: vec![],
    };
    let prompt = GuiChatConsentPrompt {
        request_id: input.request_id,
        routes: vec![GuiChatConsentRoute {
            provider: "provider".into(),
            endpoint_origin: Some("https://example.test".into()),
        }],
        expires_at_unix_ms: 1,
    };
    assert_eq!(prompt.request_id, input.request_id);
    let turn_id = gui_bridge_test_support::new_turn_id();
    let turn = gui_bridge_test_support::turn(GuiChatTurnMetadata {
        boot_id: "boot-a".into(),
        turn_id,
        origin_surface: GuiChatSurface::Main,
        phase: GuiChatPhase::Receiving,
        latest_sequence: 4,
    });
    let subscription = gui_bridge_test_support::subscription(GuiChatSubscriptionMetadata {
        boot_id: "boot-a".into(),
        turn_id,
        surface: GuiChatSurface::Buddy,
        generation: 2,
        latest_sequence: 4,
    });
    assert_eq!(turn.metadata.turn_id, subscription.metadata.turn_id);
    let response_feedback_target = GuiChatBridgeResponseFeedbackTarget {
        response_id: "aabbccddeeff00112233445566778899".into(),
        session_id: "session-w164".into(),
        revision: 0,
    };
    let response_feedback_debug = format!("{response_feedback_target:?}");
    for forbidden in ["raw_turn_id", "home", "receipt"] {
        assert!(
            !response_feedback_debug.contains(forbidden),
            "public response-feedback target Debug must not expose {forbidden}"
        );
    }
    let event = GuiChatBridgeEvent::Terminal {
        subscription: subscription.metadata.clone(),
        sequence: 5,
        state: GuiChatTerminalState::Complete,
        provider: "provider".into(),
        model: "model".into(),
        response_feedback: Some(response_feedback_target),
        response_feedback_unavailable: false,
    };
    assert!(matches!(
        event,
        GuiChatBridgeEvent::Terminal {
            sequence: 5,
            response_feedback: Some(GuiChatBridgeResponseFeedbackTarget {
                response_id,
                session_id,
                revision: 0,
            }),
            response_feedback_unavailable: false,
            ..
        } if response_id == "aabbccddeeff00112233445566778899" && session_id == "session-w164"
    ));
    let reasoning = GuiChatBridgeEvent::ReasoningState {
        subscription: subscription.metadata,
        sequence: 6,
        reasoning_sequence: 1,
        state: ReasoningTerminalState::Hidden,
        event_count: 0,
        byte_count: 0,
    };
    assert!(matches!(
        reasoning,
        GuiChatBridgeEvent::ReasoningState {
            sequence: 6,
            state: ReasoningTerminalState::Hidden,
            event_count: 0,
            byte_count: 0,
            ..
        }
    ));
    let reasoning_delta = GuiChatBridgeEvent::ReasoningDelta {
        subscription: gui_bridge_test_support::subscription(GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id,
            surface: GuiChatSurface::Buddy,
            generation: 2,
            latest_sequence: 6,
        })
        .metadata,
        sequence: 7,
        reasoning_sequence: 1,
        delta: ReasoningText::new("ephemeral reasoning".into()),
    };
    assert!(!format!("{reasoning_delta:?}").contains("ephemeral reasoning"));
    assert!(matches!(
        reasoning_delta,
        GuiChatBridgeEvent::ReasoningDelta {
            sequence: 7,
            reasoning_sequence: 1,
            ..
        }
    ));
    let checkpoint = GuiChatBridgeEvent::ReasoningCheckpoint {
        subscription: gui_bridge_test_support::subscription(GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id,
            surface: GuiChatSurface::Buddy,
            generation: 2,
            latest_sequence: 7,
        })
        .metadata,
        sequence: 8,
        reasoning_sequence: 1,
        event_count: 1,
        byte_count: 19,
    };
    assert!(matches!(
        checkpoint,
        GuiChatBridgeEvent::ReasoningCheckpoint {
            sequence: 8,
            reasoning_sequence: 1,
            event_count: 1,
            byte_count: 19,
            ..
        }
    ));
    let recall = GuiChatBridgeEvent::RecallChipBatch {
        subscription: gui_bridge_test_support::subscription(GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id,
            surface: GuiChatSurface::Main,
            generation: 2,
            latest_sequence: 8,
        })
        .metadata,
        sequence: 9,
        batch: GuiChatBridgeRecallChipBatch {
            status: GuiChatBridgeRecallChipStatus::Ready,
            rows: vec![GuiChatBridgeRecallChipRow {
                tier: GuiChatBridgeRecallChipTier::Warm,
                score: Some(0.42),
                source_state: GuiChatBridgeRecallChipSourceState::Available,
            }],
        },
    };
    assert!(matches!(
        recall,
        GuiChatBridgeEvent::RecallChipBatch {
            sequence: 9,
            batch: GuiChatBridgeRecallChipBatch {
                status: GuiChatBridgeRecallChipStatus::Ready,
                rows,
            },
            ..
        } if rows == vec![GuiChatBridgeRecallChipRow {
            tier: GuiChatBridgeRecallChipTier::Warm,
            score: Some(0.42),
            source_state: GuiChatBridgeRecallChipSourceState::Available,
        }]
    ));
    let throughput = GuiChatBridgeEvent::ThroughputState {
        subscription: gui_bridge_test_support::subscription(GuiChatSubscriptionMetadata {
            boot_id: "boot-a".into(),
            turn_id,
            surface: GuiChatSurface::Main,
            generation: 2,
            latest_sequence: 9,
        })
        .metadata,
        sequence: 10,
        throughput_sequence: 7,
        state: GuiChatBridgeThroughputState::Measuring {
            basis: GuiChatBridgeThroughputBasis::TokenDelta,
            per_second: 12.5,
        },
    };
    assert!(matches!(
        throughput,
        GuiChatBridgeEvent::ThroughputState {
            sequence: 10,
            throughput_sequence: 7,
            state: GuiChatBridgeThroughputState::Measuring {
                basis: GuiChatBridgeThroughputBasis::TokenDelta,
                per_second,
            },
            ..
        } if per_second == 12.5
    ));
    assert!(matches!(
        GuiChatConsentDecision::Deny,
        GuiChatConsentDecision::Deny
    ));
    let _preflight = gui_bridge_test_support::preflight_receipt();
    let ready = GuiChatBridgePreflight::Ready {
        decision: gui_bridge_test_support::decision_receipt(),
    };
    assert!(matches!(ready, GuiChatBridgePreflight::Ready { .. }));
    let _trait_edge: fn(&dyn GuiChatBridge) = accepts_public_bridge;
}
