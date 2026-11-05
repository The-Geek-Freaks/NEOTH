use super::*;
use tempfile::tempdir;

const OPERATOR: &str = COMMUNICATION_OPERATOR_SUBJECT;
const DIMENSION: CommunicationDimension = CommunicationDimension::ProcessingLoad;
fn compact() -> PreferenceValue { PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact) }
fn deep() -> PreferenceValue { PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep) }
fn pin(home: &Path, policy: &CommunicationProfileConfig, id: &str, value: PreferenceValue, byte: u8, at: i64) {
    assert_eq!(set(home, policy, OPERATOR, id, value, [byte; 32], at, false).unwrap().recorded, 1);
}
fn prompt(home: &Path, policy: &CommunicationProfileConfig, id: &str) -> String {
    compile_prompt_for_session(home, OPERATOR, policy, None, id, false).unwrap().unwrap().text
}

#[test]
fn session_pin_survives_reload_overrides_global_and_reset_restores_fallback() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    pin(dir.path(), &policy, "retained-session", compact(), 1, 10);
    set_explicit_preference(dir.path(), &policy, OPERATOR, "global-control", deep(), [2; 32], 100, false).unwrap();
    assert_eq!(inspect(dir.path(), &policy, OPERATOR, "retained-session", false).unwrap()[&DIMENSION], compact());
    let matching = prompt(dir.path(), &policy, "retained-session");
    assert!(matching.contains(instruction_for(compact())));
    assert!(!matching.contains(instruction_for(deep())));
    assert!(!matching.contains("retained-session"));
    assert!(matching.contains("presentation_only"));
    assert!(prompt(dir.path(), &policy, "another-session").contains(instruction_for(deep())));
    let ordinary = compile_prompt(dir.path(), OPERATOR, &policy, Some(&CommunicationScope::Session("retained-session".into())), false).unwrap().unwrap();
    assert!(ordinary.text.contains(instruction_for(deep())));
    let export = load_redacted_export(dir.path()).unwrap();
    assert_eq!(export.active_accommodations, vec![deep()]);
    assert!(reset(dir.path(), &policy, OPERATOR, "retained-session", DIMENSION, false).unwrap());
    assert!(!reset(dir.path(), &policy, OPERATOR, "retained-session", DIMENSION, false).unwrap());
    assert!(prompt(dir.path(), &policy, "retained-session").contains(instruction_for(deep())));
    pin(dir.path(), &policy, "retained-session", compact(), 3, 200);
    assert!(forget_subject(dir.path(), OPERATOR).unwrap());
    assert!(inspect(dir.path(), &policy, OPERATOR, "retained-session", false).unwrap().is_empty());
}

#[test]
fn session_pin_coexists_with_channel_scope_without_entering_generic_exports() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    let channel = CommunicationScope::Channel("retained-channel".into());
    record_evidence(dir.path(), &policy, EvidenceInput::new([1; 32], OPERATOR, "channel-control".into(), EvidenceSource::ExplicitSetting, deep(), 20, channel.clone(), "test_channel_pin"), false, false).unwrap();
    pin(dir.path(), &policy, "target", compact(), 2, 30);
    assert!(compile_prompt(dir.path(), OPERATOR, &policy, None, false).unwrap().is_none());
    assert!(load_redacted_export(dir.path()).unwrap().active_accommodations.is_empty());
    for (id, value) in [("target", compact()), ("other", deep())] {
        let compiled = compile_prompt_for_session(dir.path(), OPERATOR, &policy, Some(&channel), id, false).unwrap().unwrap();
        assert!(compiled.text.contains(instruction_for(value)));
    }
}

#[test]
fn session_pin_capacity_rejects_new_scope_atomically_and_keeps_existing_pins() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig { max_evidence_per_dimension: 8, full_auto_min_observations: 8, ..CommunicationProfileConfig::default() };
    set_explicit_preference(dir.path(), &policy, OPERATOR, "global-control", deep(), [1; 32], 1, false).unwrap();
    for index in 0..7u8 { pin(dir.path(), &policy, &format!("session-{index}"), compact(), index + 2, 10); }
    let before = std::fs::read(state_path(dir.path())).unwrap();
    assert!(set(dir.path(), &policy, OPERATOR, "overflow", compact(), [20; 32], 20, false).is_err());
    assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), before);
    pin(dir.path(), &policy, "session-0", deep(), 21, 5);
    assert_eq!(inspect(dir.path(), &policy, OPERATOR, "session-0", false).unwrap()[&DIMENSION], deep());
    assert!(reset(dir.path(), &policy, OPERATOR, "session-0", DIMENSION, false).unwrap());
    assert!(inspect(dir.path(), &policy, OPERATOR, "session-0", false).unwrap().is_empty());
    pin(dir.path(), &policy, "overflow", compact(), 20, 20);
    for index in 1..7 { assert_eq!(inspect(dir.path(), &policy, OPERATOR, &format!("session-{index}"), false).unwrap()[&DIMENSION], compact()); }
    assert_eq!(load_redacted_export(dir.path()).unwrap().active_accommodations, vec![deep()]);
}

#[test]
fn session_pin_order_survives_clock_rollback_deduplication_and_overflow() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    pin(dir.path(), &policy, "ordered", compact(), 250, 100);
    pin(dir.path(), &policy, "ordered", deep(), 2, 1);
    let before = std::fs::read(state_path(dir.path())).unwrap();
    assert_eq!(set(dir.path(), &policy, OPERATOR, "ordered", compact(), [250; 32], 100, false).unwrap().duplicates, 1);
    assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), before);
    let state = load_state(dir.path()).unwrap();
    let items = &state.subjects[OPERATOR].evidence[&DIMENSION];
    assert_eq!(items[1].observed_at_unix, 101);
    assert_eq!(inspect(dir.path(), &policy, OPERATOR, "ordered", false).unwrap()[&DIMENSION], deep());
    pin(dir.path(), &policy, "exhausted", compact(), 3, i64::MAX);
    let before = std::fs::read(state_path(dir.path())).unwrap();
    assert!(set(dir.path(), &policy, OPERATOR, "exhausted", deep(), [4; 32], 0, false).is_err());
    assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), before);
}

#[test]
fn session_scope_rejects_untrusted_or_mismatched_evidence_and_cached_projection() {
    let dir = tempdir().unwrap();
    let policy = CommunicationProfileConfig::default();
    for (subject, source, evidence_id) in [("participant", EvidenceSource::ExplicitSetting, "target"), (OPERATOR, EvidenceSource::PassiveOutcome, "target"), (OPERATOR, EvidenceSource::ExplicitSetting, "different")] {
        let input = EvidenceInput::new([1; 32], subject, evidence_id.into(), source, compact(), 1, CommunicationScope::Session("target".into()), "test_invalid_pin");
        assert!(record_evidence(dir.path(), &policy, input, false, false).is_err());
        assert!(!state_path(dir.path()).exists());
    }
    for id in ["", " padded ", "incognito-private", "bad\nline"] {
        assert!(set(dir.path(), &policy, OPERATOR, id, compact(), [2; 32], 1, false).is_err());
        assert!(!state_path(dir.path()).exists());
    }
    pin(dir.path(), &policy, "target", compact(), 3, 10);
    let mut state = load_state(dir.path()).unwrap();
    state.subjects.get_mut(OPERATOR).unwrap().evidence.get_mut(&DIMENSION).unwrap()[0].authenticated_origin = Some(AuthenticatedSubjectOrigin::LegacyAuthenticated);
    assert!(validate_loaded_state(&state).is_err());
    set_explicit_preference(dir.path(), &policy, OPERATOR, "global-control", deep(), [4; 32], 20, false).unwrap();
    let mut state = load_state(dir.path()).unwrap();
    state.subjects.get_mut(OPERATOR).unwrap().estimates.get_mut(&DIMENSION).unwrap().scope_provenance = CommunicationScope::Session("target".into());
    assert!(validate_loaded_state(&state).is_err());
}

#[test]
fn session_controls_and_prompt_bypass_profile_io_when_private_or_disabled() {
    let dir = tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("profile")).unwrap();
    std::fs::write(state_path(dir.path()), b"poisoned-profile").unwrap();
    for (enabled, incognito) in [(true, true), (false, false)] {
        let policy = CommunicationProfileConfig { enabled, ..CommunicationProfileConfig::default() };
        assert!(inspect(dir.path(), &policy, OPERATOR, "incognito-private", incognito).unwrap().is_empty());
        assert!(set(dir.path(), &policy, OPERATOR, "incognito-private", compact(), [1; 32], 1, incognito).unwrap().inactive);
        assert!(!reset(dir.path(), &policy, OPERATOR, "incognito-private", DIMENSION, incognito).unwrap());
        assert!(compile_prompt_for_session(dir.path(), OPERATOR, &policy, None, "incognito-private", incognito).unwrap().is_none());
        assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), b"poisoned-profile");
    }
}
