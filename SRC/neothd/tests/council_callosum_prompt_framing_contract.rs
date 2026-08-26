//! GOLD-R3-14 Callosum original-question framing contract. Runtime adversarial
//! behavior remains beside the private builder in `council::callosum`.

const ENVELOPE: &str = include_str!("../src/security/prompt_envelope.rs");
const CALLOSUM: &str = include_str!("../src/council/callosum.rs");

#[test]
fn callosum_has_a_dedicated_bounded_original_question_envelope() {
    for required in [
        "CallosumSynthesis",
        "Self::CallosumSynthesis => &[PromptFieldKind::OriginalQuestion]",
        "\"callosum_synthesis\"",
        "Self::OperatorTask | Self::OriginalQuestion => MAX_OPERATOR_TASK_BYTES",
    ] {
        assert!(
            ENVELOPE.contains(required),
            "missing Callosum prompt-envelope invariant: {required}"
        );
    }
}

#[test]
fn callosum_question_uses_one_framing_boundary_without_raw_fallback() {
    assert!(CALLOSUM.contains("PromptEnvelopePurpose::CallosumSynthesis"));
    assert!(CALLOSUM.contains("PromptFieldKind::OriginalQuestion"));
    assert_eq!(
        CALLOSUM.matches("serialize_untrusted_prompt(").count(),
        1,
        "Callosum must have exactly one original-question framing boundary"
    );
    for forbidden in [
        "QUESTION: {original_prompt}",
        "ORIGINAL QUESTION: {original_prompt}",
        "format!(\"QUESTION: {}\", original_prompt)",
    ] {
        assert!(
            !CALLOSUM.contains(forbidden),
            "Callosum regained a raw original-question fallback: {forbidden}"
        );
    }
}

#[test]
fn existing_profile_and_hemisphere_fences_remain_present() {
    for required in [
        "UntrustedContextClass::ProfileClaim",
        "council:operator-profile",
        "UntrustedContextClass::CouncilLeaf",
        "council:left_hemisphere",
        "council:right_hemisphere",
        "let left_context = crate::pipeline::UntrustedContext::new(",
        "let right_context = crate::pipeline::UntrustedContext::new(",
    ] {
        assert!(
            CALLOSUM.contains(required),
            "Callosum weakened a pre-existing untrusted-context fence: {required}"
        );
    }
}

#[test]
fn adversarial_rejection_and_determinism_tests_are_pinned() {
    for required in [
        "synthesis_question_is_escaped_typed_data_in_a_deterministic_envelope",
        "oversized_question_is_rejected_before_cerebellum_or_budget_charge",
        "</original_question>",
        "\\u{202e}",
        "synthesis_prompt_rejected",
    ] {
        assert!(
            CALLOSUM.contains(required),
            "missing Callosum adversarial framing contract: {required}"
        );
    }

    let budgeted = CALLOSUM.find("pub async fn resolve_with_profile_budget(").unwrap();
    let budgeted = &CALLOSUM[budgeted..];
    let build = budgeted.find("build_synthesis_prompt_with_profile(").unwrap();
    let charge = budgeted.find("budget.charge()").unwrap();
    let provider = budgeted.find("ask_with_depth_budget(").unwrap();
    assert!(build < charge && charge < provider);
}
