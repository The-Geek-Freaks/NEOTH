//! Separate-crate facade and reducer-fixture test. Alongside facade values it
//! imports only non-authorizing reasoning text/state values, never an audit
//! stream, engine event, provider capability, wire DTO, credential, or proof.

use neothd::daemon::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeEvent, GuiChatBridgePreflight, GuiChatBridgePreflightInput,
    GuiChatConsentDecision, GuiChatConsentPrompt, GuiChatConsentRoute, GuiChatPhase,
    GuiChatSubscriptionMetadata, GuiChatSurface, GuiChatTerminalState, GuiChatTurnMetadata,
    gui_bridge_test_support,
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
    let event = GuiChatBridgeEvent::Terminal {
        subscription: subscription.metadata.clone(),
        sequence: 5,
        state: GuiChatTerminalState::Complete,
        provider: "provider".into(),
        model: "model".into(),
    };
    assert!(matches!(
        event,
        GuiChatBridgeEvent::Terminal { sequence: 5, .. }
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
