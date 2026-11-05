use super::*;
use tempfile::tempdir;

const OPERATOR: &str = COMMUNICATION_OPERATOR_SUBJECT;
const DIMENSION: CommunicationDimension = CommunicationDimension::ProcessingLoad;

fn epoch(revision: u64) -> String {
    scope_id(uuid::Uuid::from_u128(123), revision).unwrap()
}
fn compact() -> PreferenceValue {
    PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact)
}
fn deep() -> PreferenceValue {
    PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep)
}
fn pin(
    home: &Path,
    policy: &CommunicationProfileConfig,
    id: &str,
    value: PreferenceValue,
    nonce: u8,
) {
    assert_eq!(
        set(home, policy, OPERATOR, id, value, [nonce; 32], 100, false)
            .unwrap()
            .recorded,
        1
    );
}
fn prompt(
    home: &Path,
    policy: &CommunicationProfileConfig,
    session: &str,
    device: &str,
) -> Option<String> {
    compile_prompt_for_admitted_device(home, OPERATOR, policy, session, Some(device), false)
        .unwrap()
        .map(|value| value.text)
}

#[test]
fn device_pin_preserves_session_precedence_epoch_isolation_and_generic_export() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    let first = epoch(1);
    set_explicit_preference(
        dir.path(),
        &policy,
        OPERATOR,
        "global",
        deep(),
        [1; 32],
        100,
        false,
    )
    .unwrap();
    pin(dir.path(), &policy, &first, compact(), 2);
    for session in ["conversation-a", "conversation-b"] {
        let rendered = prompt(dir.path(), &policy, session, &first).unwrap();
        assert!(rendered.contains(instruction_for(compact())));
        assert!(!rendered.contains(&first));
    }
    assert_eq!(
        inspect(dir.path(), &policy, OPERATOR, &first, false).unwrap()[&DIMENSION],
        compact()
    );
    for other in [epoch(2), scope_id(uuid::Uuid::from_u128(124), 1).unwrap()] {
        assert!(
            prompt(dir.path(), &policy, "conversation-a", &other)
                .unwrap()
                .contains(instruction_for(deep()))
        );
    }
    assert_eq!(
        load_redacted_export(dir.path())
            .unwrap()
            .active_accommodations,
        vec![deep()]
    );
    let generic = compile_prompt(
        dir.path(),
        OPERATOR,
        &policy,
        Some(&CommunicationScope::Device(first.clone())),
        false,
    )
    .unwrap()
    .unwrap();
    assert!(generic.text.contains(instruction_for(deep())));
    session::set(
        dir.path(),
        &policy,
        OPERATOR,
        "conversation-a",
        deep(),
        [3; 32],
        101,
        false,
    )
    .unwrap();
    assert!(
        prompt(dir.path(), &policy, "conversation-a", &first)
            .unwrap()
            .contains(instruction_for(deep()))
    );
    session::reset(
        dir.path(),
        &policy,
        OPERATOR,
        "conversation-a",
        DIMENSION,
        false,
    )
    .unwrap();
    assert!(
        prompt(dir.path(), &policy, "conversation-a", &first)
            .unwrap()
            .contains(instruction_for(compact()))
    );
    reset(dir.path(), &policy, OPERATOR, &first, DIMENSION, false).unwrap();
    assert!(
        prompt(dir.path(), &policy, "conversation-a", &first)
            .unwrap()
            .contains(instruction_for(deep()))
    );
}

#[test]
fn device_pin_old_epoch_reset_reclaims_capacity_without_transferring_preferences() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig {
        max_evidence_per_dimension: 1,
        ..Default::default()
    };
    let first = epoch(1);
    let next = epoch(2);
    pin(dir.path(), &policy, &first, compact(), 1);
    assert!(prompt(dir.path(), &policy, "continued", &next).is_none());
    let before = std::fs::read(state_path(dir.path())).unwrap();
    assert!(
        set(
            dir.path(),
            &policy,
            OPERATOR,
            &next,
            deep(),
            [2; 32],
            101,
            false
        )
        .is_err()
    );
    assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), before);
    assert!(reset(dir.path(), &policy, OPERATOR, &first, DIMENSION, false).unwrap());
    pin(dir.path(), &policy, &next, deep(), 3);
    assert!(prompt(dir.path(), &policy, "continued", &first).is_none());
    assert!(
        prompt(dir.path(), &policy, "continued", &next)
            .unwrap()
            .contains(instruction_for(deep()))
    );
    assert!(forget_subject(dir.path(), OPERATOR).unwrap());
    assert!(
        inspect(dir.path(), &policy, OPERATOR, &next, false)
            .unwrap()
            .is_empty()
    );
    assert!(prompt(dir.path(), &policy, "continued", &next).is_none());
}

#[test]
fn device_pin_rejects_bad_provenance_and_private_or_disabled_paths_do_no_io() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    let first = epoch(1);
    for invalid in [
        "",
        "not-a-device",
        "00000000-0000-0000-0000-000000000000@1",
        "00000000-0000-0000-0000-00000000007b@0",
        "00000000-0000-0000-0000-00000000007b@01",
    ] {
        assert!(validate_control_id(invalid).is_err());
    }
    assert!(
        validate_evidence(
            OPERATOR,
            Some(AuthenticatedSubjectOrigin::LocalInteractiveOperator),
            EvidenceSource::PassiveOutcome,
            &CommunicationScope::Device(first.clone()),
            &first
        )
        .is_err()
    );
    assert!(
        validate_evidence(
            OPERATOR,
            Some(AuthenticatedSubjectOrigin::PinnedChannelOperator),
            EvidenceSource::ExplicitSetting,
            &CommunicationScope::Device(first.clone()),
            &first
        )
        .is_err()
    );
    assert!(
        validate_evidence(
            OPERATOR,
            Some(AuthenticatedSubjectOrigin::LocalInteractiveOperator),
            EvidenceSource::ExplicitSetting,
            &CommunicationScope::Device(first.clone()),
            &epoch(2)
        )
        .is_err()
    );
    for (subject, source, evidence_epoch) in [
        (
            "participant",
            EvidenceSource::ExplicitSetting,
            first.clone(),
        ),
        (OPERATOR, EvidenceSource::PassiveOutcome, first.clone()),
        (OPERATOR, EvidenceSource::ExplicitSetting, epoch(2)),
    ] {
        let input = EvidenceInput::new(
            [5; 32],
            subject,
            evidence_epoch,
            source,
            compact(),
            1,
            CommunicationScope::Device(first.clone()),
            "test_invalid_device_pin",
        );
        assert!(record_evidence(dir.path(), &policy, input, false, false).is_err());
        assert!(!state_path(dir.path()).exists());
    }
    pin(dir.path(), &policy, &first, compact(), 6);
    let mut state = load_state(dir.path()).unwrap();
    state
        .subjects
        .get_mut(OPERATOR)
        .unwrap()
        .evidence
        .get_mut(&DIMENSION)
        .unwrap()[0]
        .authenticated_origin = Some(AuthenticatedSubjectOrigin::LegacyAuthenticated);
    assert!(validate_loaded_state(&state).is_err());
    set_explicit_preference(
        dir.path(),
        &policy,
        OPERATOR,
        "global-control",
        deep(),
        [7; 32],
        102,
        false,
    )
    .unwrap();
    let mut state = load_state(dir.path()).unwrap();
    state
        .subjects
        .get_mut(OPERATOR)
        .unwrap()
        .estimates
        .get_mut(&DIMENSION)
        .unwrap()
        .scope_provenance = CommunicationScope::Device(first.clone());
    assert!(validate_loaded_state(&state).is_err());
    let blocked = dir.path().join("not-a-directory");
    std::fs::write(&blocked, b"unchanged").unwrap();
    for (enabled, incognito) in [(true, true), (false, false)] {
        let policy = CommunicationProfileConfig {
            enabled,
            ..policy.clone()
        };
        assert!(
            inspect(&blocked, &policy, OPERATOR, "invalid", incognito)
                .unwrap()
                .is_empty()
        );
        assert!(
            set(
                &blocked,
                &policy,
                OPERATOR,
                "invalid",
                compact(),
                [4; 32],
                100,
                incognito
            )
            .unwrap()
            .inactive
        );
        assert!(!reset(&blocked, &policy, OPERATOR, "invalid", DIMENSION, incognito).unwrap());
        assert!(
            compile_prompt_for_admitted_device(
                &blocked,
                OPERATOR,
                &policy,
                "invalid",
                Some("invalid"),
                incognito
            )
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(std::fs::read(blocked).unwrap(), b"unchanged");
}
