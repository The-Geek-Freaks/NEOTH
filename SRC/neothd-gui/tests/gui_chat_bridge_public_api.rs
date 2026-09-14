//! Separate-crate facade and reducer-fixture test. It imports no
//! audit stream, engine event, provider, wire DTO, credential, or proof type.

use neothd::daemon::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeEvent, GuiChatBridgePreflight, GuiChatBridgePreflightInput,
    GuiChatConsentDecision, GuiChatConsentPrompt, GuiChatConsentRoute, GuiChatPhase,
    GuiChatSubscriptionMetadata, GuiChatSurface, GuiChatTerminalState, GuiChatTurnMetadata,
    gui_bridge_test_support,
};

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
        subscription: subscription.metadata,
        sequence: 5,
        state: GuiChatTerminalState::Complete,
        provider: "provider".into(),
        model: "model".into(),
    };
    assert!(matches!(
        event,
        GuiChatBridgeEvent::Terminal { sequence: 5, .. }
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
