//! GOLD-R3-14 Council self-reflect consumer source contract. Behavioral and
//! adversarial tests remain beside the private prompt builder and serializer.

const ENVELOPE: &str = include_str!("../src/security/prompt_envelope.rs");
const SELF_REFLECT: &str = include_str!("../src/council/self_reflect.rs");

#[test]
fn council_self_reflect_has_a_dedicated_typed_schema() {
    for required in [
        "CouncilSelfReflect",
        "PromptFieldKind::OriginalQuestion",
        "PromptFieldKind::PriorAnswer",
        "\"council_self_reflect\"",
        "\"original_question\"",
        "\"prior_answer\"",
    ] {
        assert!(
            ENVELOPE.contains(required),
            "missing Council self-reflect envelope invariant: {required}"
        );
    }
    assert!(ENVELOPE.contains(
        "Self::OperatorTask | Self::OriginalQuestion => MAX_OPERATOR_TASK_BYTES"
    ));
    assert!(ENVELOPE.contains("Self::PriorAnswer => MAX_CANDIDATE_BYTES"));
}

#[test]
fn council_self_reflect_crosses_the_serializer_exactly_once() {
    assert!(SELF_REFLECT.contains("PromptEnvelopePurpose::CouncilSelfReflect"));
    assert!(SELF_REFLECT.contains("PromptFieldKind::OriginalQuestion"));
    assert!(SELF_REFLECT.contains("PromptFieldKind::PriorAnswer"));
    assert_eq!(
        SELF_REFLECT.matches("serialize_untrusted_prompt(").count(),
        1,
        "the self-reflect builder must have one framing boundary"
    );
    for forbidden in [
        "=== ORIGINAL QUESTION ===",
        "=== YOUR PRIOR ANSWER ===",
        "{original_prompt}",
        "{original_text}",
    ] {
        assert!(
            !SELF_REFLECT.contains(forbidden),
            "self-reflect regained direct interpolation: {forbidden}"
        );
    }
}

#[test]
fn framing_rejection_precedes_provider_and_budget_side_effects() {
    assert_eq!(
        SELF_REFLECT
            .matches("Err(_) => return prompt_rejected(original_text)")
            .count(),
        2,
        "both public refine paths must fail closed on envelope rejection"
    );

    let budgeted = SELF_REFLECT.find("pub async fn refine_with_budget(").unwrap();
    let budgeted = &SELF_REFLECT[budgeted..];
    let build = budgeted.find("build_reflect_prompt(").unwrap();
    let charge = budgeted.find("budget.charge()").unwrap();
    let provider = budgeted.find("ask_with_depth_budget(").unwrap();
    assert!(build < charge && charge < provider);
}

#[test]
fn adversarial_and_no_side_effect_tests_are_pinned() {
    for required in [
        "reflect_prompt_keeps_markup_controls_and_bidi_inside_typed_fields",
        "reflect_prompt_is_deterministic_and_uses_canonical_field_order",
        "oversized_question_is_rejected_before_provider_call",
        "oversized_answer_is_rejected_before_budget_charge_or_provider_call",
        "</original_question>",
        "</prior_answer>",
        "\\u{202e}",
        "prompt_rejected",
    ] {
        assert!(
            SELF_REFLECT.contains(required),
            "missing Council self-reflect adversarial contract: {required}"
        );
    }
}
