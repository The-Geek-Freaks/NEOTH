//! Passive Self-improve quality snapshot for read-only status consumers.
//!
//! This module must never acquire `with_state_lock`: that path creates the
//! state lock and runs installed-Skill and Self-improve transaction recovery.
//! A Buddy status read publishes only a bounded clear-before/after observation;
//! it is not an atomic lock-free lifecycle snapshot.

use serde::Serialize;
use std::path::Path;

const PASSIVE_UNAVAILABLE_RECOVERY: &str =
    "self-improve quality is unavailable while recovery is pending or cannot be inspected";
const PASSIVE_UNAVAILABLE_PROPOSALS: &str =
    "self-improve quality is unavailable because the proposal snapshot is unreadable";
const MAX_PUBLIC_ID_BYTES: usize = 256;
const MAX_PUBLIC_SKILL_BYTES: usize = 256;
const MAX_PUBLIC_SUMMARY_BYTES: usize = 512;

/// All-or-unavailable quality projection for a passive status surface.
///
/// `Available` means recovery was observed clear before the raw proposal read
/// and again after every row's core quality projection. It is an observation,
/// never lifecycle authorization; later mutation must use the normal
/// locked/recovered path.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum PassiveQualitySnapshot {
    Available {
        proposals: Vec<PassiveQualityProposal>,
    },
    Unavailable {
        reason: &'static str,
    },
}

/// Compact proposal identity/status plus the exact W142 core quality readback.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PassiveQualityProposal {
    pub id: String,
    pub skill: String,
    pub summary: String,
    pub status: super::ProposalStatus,
    pub quality: super::ProposalQualityReadback,
}

/// Read one bounded, non-recovering observation for Buddy and similarly passive
/// consumers. It neither creates a lock nor reconciles/recovery-writes state.
pub(crate) fn quality_snapshot(home: &Path) -> PassiveQualitySnapshot {
    // A transaction journal is an incomplete multi-file state by definition.
    // The final probe is intentionally after every quality projection because
    // that projection reloads live verifier/corpus authority.
    if !recovery_domains_clear(home) {
        return unavailable_recovery();
    }

    let proposals = match super::load_proposals_raw(home) {
        Ok(proposals) => proposals,
        Err(_) => return unavailable_proposals(),
    };

    let Some(rows) = proposals
        .iter()
        .map(|proposal| passive_row(home, proposal))
        .collect::<Option<Vec<_>>>()
    else {
        // Identity fields are identifiers, not display prose. Do not redact or
        // clip them into a different identifier; reject the entire observation.
        return unavailable_proposals();
    };

    run_before_final_recovery_probe_for_test();
    if !recovery_domains_clear(home) {
        return unavailable_recovery();
    }

    PassiveQualitySnapshot::Available { proposals: rows }
}

fn passive_row(home: &Path, proposal: &super::Proposal) -> Option<PassiveQualityProposal> {
    Some(PassiveQualityProposal {
        id: exact_public_identity(&proposal.id, MAX_PUBLIC_ID_BYTES)?,
        skill: exact_public_identity(&proposal.skill, MAX_PUBLIC_SKILL_BYTES)?,
        summary: bounded_public_summary(&proposal.summary, MAX_PUBLIC_SUMMARY_BYTES),
        status: proposal.status,
        // W142 owns evidence validation, live verifier/corpus revalidation,
        // reasons, and the full eleven-field readback.
        quality: super::proposal_quality_readback(home, proposal),
    })
}

fn recovery_domains_clear(home: &Path) -> bool {
    // This helper is expressly read-only: no mutation lock, metadata creation,
    // cleanup, or reconciliation. An inspection error is conservatively not
    // clear, because Buddy must not report success from partial authority.
    match crate::skills::installer::skill_mutation_recovery_pending_read_only(&home.join("skills"))
    {
        Ok(false) => {}
        Ok(true) | Err(_) => return false,
    }

    journal_absent(
        &super::journal_path(home),
        super::SELF_IMPROVE_ACCEPT_JOURNAL_MAX_BYTES,
        "accept journal",
    ) && journal_absent(
        &super::stage_journal_path(home),
        super::SELF_IMPROVE_STAGE_JOURNAL_MAX_BYTES,
        "stage journal",
    )
}

fn journal_absent(path: &Path, max_bytes: usize, label: &str) -> bool {
    // Presence is sufficient to make the observation unavailable. Deliberately
    // do not parse or recover the journal: malformed and unreadable journals
    // also remain unavailable rather than becoming false success.
    matches!(
        super::read_optional_regular_file_bounded(path, max_bytes, label),
        Ok(None)
    )
}

fn unavailable_recovery() -> PassiveQualitySnapshot {
    PassiveQualitySnapshot::Unavailable {
        reason: PASSIVE_UNAVAILABLE_RECOVERY,
    }
}

fn unavailable_proposals() -> PassiveQualitySnapshot {
    PassiveQualitySnapshot::Unavailable {
        reason: PASSIVE_UNAVAILABLE_PROPOSALS,
    }
}

fn exact_public_identity(value: &str, max_bytes: usize) -> Option<String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(|ch| ch.is_control()) {
        return None;
    }
    // A differing sanitizer result proves output would not preserve the exact
    // persisted identity. In that case unavailable is safer than an alias.
    (crate::security::redact::sanitize_tool_output(value) == value).then(|| value.to_owned())
}

fn bounded_public_summary(value: &str, max_bytes: usize) -> String {
    let sanitized = crate::security::redact::sanitize_tool_output(value);
    if sanitized.len() <= max_bytes {
        return sanitized;
    }
    let mut end = max_bytes;
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &sanitized[..end])
}

#[cfg(test)]
thread_local! {
    static BEFORE_FINAL_RECOVERY_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_before_final_recovery_probe_for_test() {
    if let Some(hook) = BEFORE_FINAL_RECOVERY_PROBE.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn run_before_final_recovery_probe_for_test() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_or_malformed_stage_journal_is_unavailable_without_recovery_or_lock_creation() {
        let home = tempfile::tempdir().expect("temporary self-improve home");
        let journal = super::super::stage_journal_path(home.path());
        std::fs::write(&journal, b"{not valid journal json").expect("write malformed journal");
        let before = std::fs::read(&journal).expect("read journal before passive observation");

        let snapshot = quality_snapshot(home.path());

        assert!(matches!(
            snapshot,
            PassiveQualitySnapshot::Unavailable { .. }
        ));
        assert_eq!(
            std::fs::read(&journal).expect("passive observation retains journal"),
            before,
            "passive status must not parse, repair, or remove a recovery journal"
        );
        assert!(
            !super::super::state_lock_path(home.path()).exists(),
            "passive status must not create the normal Self-improve state lock"
        );
    }

    #[test]
    fn final_recovery_probe_rejects_a_transition_observed_after_quality_projection() {
        let home = tempfile::tempdir().expect("temporary self-improve home");
        let proposal = super::super::Proposal {
            id: "quality-before-final-probe".to_string(),
            skill: "skills/passive.md".to_string(),
            summary: "quality projection must not outrun final recovery probe".to_string(),
            ..Default::default()
        };
        super::super::save_proposals_raw(home.path(), std::slice::from_ref(&proposal))
            .expect("write strict raw proposal fixture");
        let journal = super::super::stage_journal_path(home.path());
        let journal_for_hook = journal.clone();
        BEFORE_FINAL_RECOVERY_PROBE.with(|slot| {
            slot.replace(Some(Box::new(move || {
                std::fs::write(&journal_for_hook, b"pending after quality projection")
                    .expect("create pending journal before final probe");
            })));
        });

        let snapshot = quality_snapshot(home.path());

        assert!(matches!(
            snapshot,
            PassiveQualitySnapshot::Unavailable { .. }
        ));
        assert!(
            journal.exists(),
            "final probe must not recover the observed journal"
        );
        assert!(
            !super::super::state_lock_path(home.path()).exists(),
            "final recovery probe must remain lock-free"
        );
    }

    #[test]
    fn strict_raw_proposals_preserve_exact_identity_and_shared_quality_readback() {
        let home = tempfile::tempdir().expect("temporary self-improve home");
        let proposal = super::super::Proposal {
            id: "passive-quality-row".to_string(),
            skill: "skills/passive.md".to_string(),
            summary: "bounded passive quality row".to_string(),
            ..Default::default()
        };
        super::super::save_proposals_raw(home.path(), std::slice::from_ref(&proposal))
            .expect("write strict raw proposal fixture");

        let snapshot = quality_snapshot(home.path());

        let PassiveQualitySnapshot::Available { proposals } = snapshot else {
            panic!("clear recovery state and strict raw proposal must be available");
        };
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].id, proposal.id,
            "id must not be redacted or clipped"
        );
        assert_eq!(
            proposals[0].skill, proposal.skill,
            "skill must not be redacted or clipped"
        );
        assert_eq!(proposals[0].status, super::super::ProposalStatus::Pending);
        assert_eq!(
            proposals[0].quality.state,
            super::super::ProposalQualityState::Incomplete,
            "missing fixed-corpus evidence must remain the core-owned incomplete state"
        );
        assert!(
            !super::super::state_lock_path(home.path()).exists(),
            "a valid passive projection must not acquire or create the recovery lock"
        );
    }

    #[test]
    fn altered_or_control_identity_makes_the_entire_snapshot_unavailable() {
        let home = tempfile::tempdir().expect("temporary self-improve home");
        let proposal = super::super::Proposal {
            id: "proposal\nnot-an-exact-identity".to_string(),
            skill: "skills/passive.md".to_string(),
            ..Default::default()
        };
        super::super::save_proposals_raw(home.path(), std::slice::from_ref(&proposal))
            .expect("write strict raw proposal fixture");

        assert!(matches!(
            quality_snapshot(home.path()),
            PassiveQualitySnapshot::Unavailable { .. }
        ));
    }
}
