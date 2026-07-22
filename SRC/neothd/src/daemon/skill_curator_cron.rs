//! GOLD-FEAT-11 — approved-skill reconciliation cron.
//!
//! The proposal producer, operator review CLI and this consumer all use the
//! typed `ProposedAction` schema. Explicit `neoth proactive accept` adopts a
//! skill immediately; this optional cron is the repair/reconciliation path for
//! Approved or recoverable Applying proposals whose exact Generated install or Active
//! proposal-bound authority did not finish.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::config::automation::SkillCuratorConfig;
use crate::proactive::action_staging::{
    ProposalKind, ProposalStatus, adopt_approved_skill, list_proposals,
};

/// Reconcile mature approved Skill proposals into the live skill directory.
///
/// The age gate uses `ProposedAction::generated_ts_unix`; approval uses the
/// authenticated `ProposalStatus::Approved`/`Applying` lifecycle. Historical
/// Applied, Revoked, Pending, and Rejected proposals never reach adoption.
pub async fn run_skill_curator_tick(
    home: &Path,
    cfg: &SkillCuratorConfig,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }

    let now_unix = crate::time::now_unix_i64();
    let min_age_secs = cfg.min_age_days.saturating_mul(86_400) as i64;
    let proposal_home = home.to_path_buf();
    let proposals = tokio::task::spawn_blocking(move || list_proposals(&proposal_home, None))
        .await
        .map_err(|error| anyhow::anyhow!("skill curator proposal scan worker failed: {error}"))??;
    let mut promoted = 0usize;
    let mut promoted_with_warnings = 0usize;

    for proposal in proposals {
        if proposal.kind != ProposalKind::Skill
            || !matches!(
                proposal.status,
                ProposalStatus::Approved | ProposalStatus::Applying
            )
        {
            continue;
        }
        let age_secs = now_unix.saturating_sub(proposal.generated_ts_unix);
        if age_secs < min_age_secs {
            debug!(
                proposal_id = %proposal.id,
                age_secs,
                min_age_secs,
                "skill_curator: adoptable proposal not mature yet"
            );
            continue;
        }

        match adopt_approved_skill(home, &proposal, writer).await {
            Ok(report) => {
                promoted += 1;
                let warning_count = report.warnings.len();
                if warning_count > 0 {
                    promoted_with_warnings += 1;
                    for warning in crate::skills::operator_skill_warnings(&report.warnings) {
                        warn!(
                            proposal_id = %proposal.id,
                            skill_id = %report.id,
                            %warning,
                            "skill_curator: reconciled approved skill with durability warning"
                        );
                    }
                }
                info!(
                    proposal_id = %proposal.id,
                    skill_id = %report.id,
                    dest = %report.installed_at.display(),
                    installed_new = report.installed_new,
                    authority_changed = report.authority_changed,
                    provenance = ?report.provenance,
                    authority_state = ?report.authority_state,
                    install_manifest_sha256 = %report.install_manifest_sha256,
                    install_package_generation_sha256 = %report.install_package_generation_sha256,
                    pending_installed_generation_sha256 = %report.pending_installed_generation_sha256,
                    authority_installed_generation_sha256 = %report.authority_installed_generation_sha256,
                    authority_record_sha256 = %report.authority_record_sha256,
                    warning_count,
                    "skill_curator: reconciled approved generated skill authority"
                );
            }
            Err(error) => {
                warn!(
                    proposal_id = %proposal.id,
                    error = %error,
                    "skill_curator: generated skill reconciliation failed"
                );
            }
        }
    }

    if promoted > 0 {
        info!(
            promoted,
            promoted_with_warnings, "skill_curator: tick complete"
        );
    } else {
        debug!("skill_curator: no proposals reconciled this tick");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::{
        ProposedAction, load_proposal, make_proposal_id,
        revoke_generated_skill_proposals_for_skill_id, set_proposal_status, stage_and_enqueue,
    };
    use crate::skills::creator::{CreateParams, build_manifest};
    use tempfile::tempdir;

    fn default_cfg() -> SkillCuratorConfig {
        SkillCuratorConfig {
            enabled: true,
            interval_secs: 7 * 86_400,
            min_age_days: 7,
        }
    }

    fn skill_proposal(id: &str, age_days: i64, status: ProposalStatus) -> ProposedAction {
        let (_, draft_yaml) = build_manifest(&CreateParams {
            id: id.to_string(),
            description: format!("{id} test skill"),
            keywords: vec!["test".to_string()],
            system_prompt: "Follow the tested workflow.".to_string(),
        })
        .unwrap();
        let generated_ts_unix = crate::time::now_unix_i64() - age_days * 86_400;
        ProposedAction {
            id: make_proposal_id(
                ProposalKind::Skill,
                &format!("Skill: {id}"),
                &draft_yaml,
                generated_ts_unix,
            ),
            kind: ProposalKind::Skill,
            title: format!("Skill: {id}"),
            rationale: "test".to_string(),
            draft_yaml,
            generated_ts_unix,
            status,
            operator_note: String::new(),
        }
    }

    fn persist_proposal(home: &Path, proposal: &ProposedAction) {
        let mut pending = proposal.clone();
        pending.status = ProposalStatus::Pending;
        pending.operator_note.clear();
        crate::proactive::action_staging::save_proposal(home, &pending).unwrap();
        if proposal.status != ProposalStatus::Pending {
            set_proposal_status(home, &pending.id, proposal.status, "test verdict").unwrap();
        }
    }

    #[tokio::test]
    async fn no_op_when_disabled_or_no_proposals_exist() {
        let dir = tempdir().unwrap();
        let mut cfg = default_cfg();
        cfg.enabled = false;
        run_skill_curator_tick(dir.path(), &cfg, None)
            .await
            .unwrap();
        cfg.enabled = true;
        run_skill_curator_tick(dir.path(), &cfg, None)
            .await
            .unwrap();
        assert!(!dir.path().join("skills").exists());
    }

    #[tokio::test]
    async fn producer_schema_approval_and_curator_form_one_live_path() {
        let dir = tempdir().unwrap();
        let proposal = skill_proposal("curated_skill", 10, ProposalStatus::Pending);
        let proposal_id = proposal.id.clone();
        let mut queue = ProactiveQueue::default();
        stage_and_enqueue(dir.path(), proposal, &mut queue).unwrap();
        set_proposal_status(
            dir.path(),
            &proposal_id,
            ProposalStatus::Approved,
            "ship it",
        )
        .unwrap();

        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();
        let dest = dir
            .path()
            .join("skills")
            .join("curated_skill")
            .join("skill.yaml");
        assert!(dest.exists(), "approved producer proposal must become live");
        assert!(
            std::fs::read_to_string(dest)
                .unwrap()
                .contains("curated_skill")
        );
        let loaded = crate::skills::loader::load_all(&dir.path().join("skills"))
            .await
            .unwrap();
        let skill = loaded
            .iter()
            .find(|skill| skill.id() == "curated_skill")
            .unwrap();
        assert_eq!(
            skill.provenance(),
            crate::skills::authority::SkillProvenance::Generated
        );
        assert_eq!(
            skill.authority_state(),
            crate::skills::authority::SkillAuthorityState::Active
        );
        assert!(skill.is_routable());
        assert_eq!(
            load_proposal(dir.path(), &proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applied
        );

        let first_generation = crate::skills::installer::inspect_installed_authority(
            &dir.path().join("skills"),
            "curated_skill",
        )
        .unwrap()
        .installed_generation_sha256;
        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();
        let second_generation = crate::skills::installer::inspect_installed_authority(
            &dir.path().join("skills"),
            "curated_skill",
        )
        .unwrap()
        .installed_generation_sha256;
        assert_eq!(
            first_generation, second_generation,
            "Applied must be a no-op"
        );
    }

    #[tokio::test]
    async fn revoked_applied_proposal_never_reinstalls_an_absent_target() {
        let dir = tempdir().unwrap();
        let proposal = skill_proposal("revoked_curated_skill", 10, ProposalStatus::Approved);
        let proposal_id = proposal.id.clone();
        persist_proposal(dir.path(), &proposal);
        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();

        let revoked = revoke_generated_skill_proposals_for_skill_id(
            dir.path(),
            "revoked_curated_skill",
            "test uninstall",
        )
        .unwrap();
        assert_eq!(revoked.revoked_proposal_ids, vec![proposal_id.clone()]);
        crate::skills::installer::uninstall(&dir.path().join("skills"), "revoked_curated_skill")
            .unwrap();

        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();
        assert!(
            !dir.path()
                .join("skills")
                .join("revoked_curated_skill")
                .exists()
        );
        assert_eq!(
            load_proposal(dir.path(), &proposal_id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Revoked
        );
    }

    #[tokio::test]
    async fn applying_with_absent_target_never_becomes_a_fresh_install() {
        let dir = tempdir().unwrap();
        let proposal = skill_proposal("applying_absent", 10, ProposalStatus::Approved);
        persist_proposal(dir.path(), &proposal);
        let approved = load_proposal(dir.path(), &proposal.id).unwrap().unwrap();
        std::fs::write(dir.path().join("skills"), b"block installer").unwrap();
        adopt_approved_skill(dir.path(), &approved, None)
            .await
            .unwrap_err();
        std::fs::remove_file(dir.path().join("skills")).unwrap();
        assert_eq!(
            load_proposal(dir.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applying
        );

        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();
        assert!(!dir.path().join("skills").exists());
    }

    #[tokio::test]
    async fn pending_or_too_young_proposals_do_not_promote() {
        for proposal in [
            skill_proposal("pending_skill", 10, ProposalStatus::Pending),
            skill_proposal("young_skill", 2, ProposalStatus::Approved),
        ] {
            let dir = tempdir().unwrap();
            persist_proposal(dir.path(), &proposal);
            run_skill_curator_tick(dir.path(), &default_cfg(), None)
                .await
                .unwrap();
            assert!(!dir.path().join("skills").exists());
        }
    }

    #[tokio::test]
    async fn non_skill_and_invalid_skill_drafts_fail_closed() {
        let dir = tempdir().unwrap();
        let mut invalid = skill_proposal("invalid_skill", 10, ProposalStatus::Approved);
        invalid.draft_yaml = "- not\n- a\n- manifest\n".to_string();
        persist_proposal(dir.path(), &invalid);

        let mut non_skill = skill_proposal("not_a_skill", 10, ProposalStatus::Approved);
        non_skill.kind = ProposalKind::ConfigTweak;
        non_skill.id = format!("{}-config", non_skill.id);
        persist_proposal(dir.path(), &non_skill);

        run_skill_curator_tick(dir.path(), &default_cfg(), None)
            .await
            .unwrap();
        assert!(!dir.path().join("skills").exists());
    }
}
