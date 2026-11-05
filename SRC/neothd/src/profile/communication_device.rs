//! Explicit device presentation controls within the existing profile owner.
//! Device ids and preference values never enter the provider-facing header.
use super::*;

pub(crate) fn validate_control_id(id: &str) -> Result<()> {
    validate_id(id)
}

/// Exact pairing epoch; reconnect preserves it and revocation/re-pair changes it.
pub(crate) fn scope_id(id: uuid::Uuid, revision: u64) -> Result<String> {
    anyhow::ensure!(!id.is_nil() && revision > 0, "invalid device presentation epoch");
    Ok(format!("{id}@{revision}"))
}

pub(super) fn validate_id(id: &str) -> Result<()> {
    let (device, revision) = id.split_once('@').context("invalid device presentation epoch")?;
    let canonical = scope_id(uuid::Uuid::parse_str(device)?, revision.parse()?)?;
    anyhow::ensure!(canonical == id, "noncanonical device presentation epoch");
    Ok(())
}
pub(super) fn validate_evidence(
    subject: &str,
    origin: Option<AuthenticatedSubjectOrigin>,
    source: EvidenceSource,
    scope: &CommunicationScope,
    evidence_session: &str,
) -> Result<()> {
    if let CommunicationScope::Device(id) = scope {
        validate_id(id)?;
        anyhow::ensure!(
            subject == COMMUNICATION_OPERATOR_SUBJECT
                && matches!(
                    origin,
                    Some(AuthenticatedSubjectOrigin::LocalInteractiveOperator)
                )
                && source == EvidenceSource::ExplicitSetting
                && id == evidence_session,
            "device preference lacks exact explicit operator-device provenance"
        );
    }
    Ok(())
}

pub(super) fn selected(
    subject: &SubjectCommunicationProfile,
    device_id: &str,
    dimension: CommunicationDimension,
) -> Option<PreferenceValue> {
    subject
        .evidence
        .get(&dimension)?
        .iter()
        .filter(|item| {
            item.source == EvidenceSource::ExplicitSetting
                && matches!(&item.scope, CommunicationScope::Device(id) if id == device_id)
        })
        .max_by(|left, right| {
            (left.observed_at_unix, left.event_hash.as_str())
                .cmp(&(right.observed_at_unix, right.event_hash.as_str()))
        })
        .map(|item| item.value)
}

pub(crate) fn inspect(
    home: &Path,
    policy: &CommunicationProfileConfig,
    proof: impl ApprovedCommunicationSubject,
    device_id: &str,
    incognito: bool,
) -> Result<BTreeMap<CommunicationDimension, PreferenceValue>> {
    if !policy.enabled || incognito {
        return Ok(BTreeMap::new());
    }
    let subject = proof.into_subject();
    anyhow::ensure!(
        subject.permits_global_scope(),
        "device controls require operator authority"
    );
    validate_id(device_id)?;
    let state = load_state(home)?;
    let Some(profile) = state.subjects.get(subject.subject_id()) else {
        return Ok(BTreeMap::new());
    };
    Ok(CommunicationDimension::ALL
        .into_iter()
        .filter_map(|dimension| {
            selected(profile, device_id, dimension).map(|value| (dimension, value))
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set(
    home: &Path,
    policy: &CommunicationProfileConfig,
    proof: impl ApprovedCommunicationSubject,
    device_id: &str,
    value: PreferenceValue,
    event_hash: [u8; 32],
    observed_at_unix: i64,
    incognito: bool,
) -> Result<ObservationOutcome> {
    if !policy.enabled || incognito {
        return Ok(ObservationOutcome {
            inactive: true,
            ..ObservationOutcome::default()
        });
    }
    let subject = proof.into_subject();
    anyhow::ensure!(
        subject.permits_global_scope(),
        "device controls require operator authority"
    );
    validate_id(device_id)?;
    record_evidence(
        home,
        policy,
        EvidenceInput::from_authenticated(
            event_hash,
            subject,
            device_id.to_owned(),
            EvidenceSource::ExplicitSetting,
            value,
            observed_at_unix,
            CommunicationScope::Device(device_id.to_owned()),
            "explicit_device_setting",
        ),
        false,
        false,
    )
}

/// Clears all superseded pins in this exact scope, so reset cannot revive one.
/// The CLI requires a separate post-commit control audit, as for global reset.
pub(crate) fn reset(
    home: &Path,
    policy: &CommunicationProfileConfig,
    proof: impl ApprovedCommunicationSubject,
    device_id: &str,
    dimension: CommunicationDimension,
    incognito: bool,
) -> Result<bool> {
    if !policy.enabled || incognito {
        return Ok(false);
    }
    let subject = proof.into_subject();
    anyhow::ensure!(
        subject.permits_global_scope(),
        "device controls require operator authority"
    );
    validate_id(device_id)?;
    with_state_lock(home, || {
        let mut state = load_state_unlocked(home)?;
        let Some(profile) = state.subjects.get_mut(subject.subject_id()) else {
            return Ok(false);
        };
        let Some(items) = profile.evidence.get_mut(&dimension) else {
            return Ok(false);
        };
        let before = items.len();
        items.retain(
            |item| !matches!(&item.scope, CommunicationScope::Device(id) if id == device_id),
        );
        let changed = items.len() != before;
        if changed {
            if items.is_empty() {
                profile.evidence.remove(&dimension);
            }
            recompute_subject(profile, policy, crate::time::now_unix_i64(), false);
            profile.revision = profile.revision.saturating_add(1);
            state.revision = state.revision.saturating_add(1);
            persist_state_unlocked(home, &state)?;
        }
        Ok(changed)
    })
}

#[cfg(test)]
#[path = "communication_device_tests.rs"]
mod tests;
