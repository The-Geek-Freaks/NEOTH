//! GOLD-FEAT-11 — approved-skill reconciliation cron.
//!
//! The proposal producer, operator review CLI and this consumer all use the
//! typed `ProposedAction` schema. Explicit `neoth proactive accept` adopts a
//! skill immediately; this optional cron is the repair/reconciliation path for
//! approved proposals whose live write previously failed or pre-dates that
//! direct adoption wiring.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::config::automation::SkillCuratorConfig;
use crate::proactive::action_staging::{
    ProposalKind, ProposalStatus, SkillReconciliation, list_proposals, reconcile_approved_skill,
};

/// Reconcile mature approved Skill proposals into the live skill directory.
///
/// The age gate uses `ProposedAction::generated_ts_unix`; approval uses the
/// real `ProposalStatus::Approved`; the live YAML is the producer's
/// `draft_yaml`. Reconciliation parses the real `SkillManifest`, validates its
/// id, and publishes a complete cloned package generation only after its
/// exact curator-origin intent is authenticated in the home-bound WAL.
pub async fn run_skill_curator_tick(home: &Path, cfg: &SkillCuratorConfig) -> anyhow::Result<()> {
    let home = home.to_path_buf();
    let cfg = *cfg;
    tokio::task::spawn_blocking(move || run_skill_curator_tick_blocking(&home, &cfg))
        .await
        .map_err(|error| anyhow::anyhow!("skill curator filesystem worker failed: {error}"))?
}

fn run_skill_curator_tick_blocking(home: &Path, cfg: &SkillCuratorConfig) -> anyhow::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }

    let now_unix = crate::time::now_unix_i64();
    let min_age_secs = cfg.min_age_days.saturating_mul(86_400) as i64;
    let proposals = list_proposals(home, Some(ProposalStatus::Approved))?;
    let mut promoted = 0usize;
    let mut promoted_with_warnings = 0usize;

    for proposal in proposals {
        if proposal.kind != ProposalKind::Skill {
            continue;
        }
        let age_secs = now_unix.saturating_sub(proposal.generated_ts_unix);
        if age_secs < min_age_secs {
            debug!(
                proposal_id = %proposal.id,
                age_secs,
                min_age_secs,
                "skill_curator: approved proposal not mature yet"
            );
            continue;
        }

        match reconcile_approved_skill(home, &proposal) {
            Ok(SkillReconciliation::OperatorModified { id }) => {
                // The operator edited the adopted skill — the normal follow-up.
                // Overwriting it was the original bug; erroring on it every tick
                // forever was the fix's own defect. Leave it alone, quietly.
                debug!(
                    proposal_id = %proposal.id,
                    skill_id = %id,
                    "skill_curator: adopted skill was modified by the operator; leaving it as is"
                );
            }
            Ok(SkillReconciliation::Adopted(report)) => {
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
                    dest = %report.path.display(),
                    warning_count,
                    "skill_curator: reconciled approved skill"
                );
            }
            Err(error) => {
                warn!(
                    proposal_id = %proposal.id,
                    error = %error,
                    "skill_curator: approved skill reconciliation failed"
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
        ProposedAction, make_proposal_id, set_proposal_status, stage_and_enqueue,
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

    #[tokio::test]
    async fn no_op_when_disabled_or_no_proposals_exist() {
        let dir = tempdir().unwrap();
        let mut cfg = default_cfg();
        cfg.enabled = false;
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        cfg.enabled = true;
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
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

        run_skill_curator_tick(dir.path(), &default_cfg())
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
    }

    #[tokio::test]
    async fn pending_or_too_young_proposals_do_not_promote() {
        for proposal in [
            skill_proposal("pending_skill", 10, ProposalStatus::Pending),
            skill_proposal("young_skill", 2, ProposalStatus::Approved),
        ] {
            let dir = tempdir().unwrap();
            crate::proactive::action_staging::save_proposal(dir.path(), &proposal).unwrap();
            run_skill_curator_tick(dir.path(), &default_cfg())
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
        crate::proactive::action_staging::save_proposal(dir.path(), &invalid).unwrap();

        let mut non_skill = skill_proposal("not_a_skill", 10, ProposalStatus::Approved);
        non_skill.kind = ProposalKind::ConfigTweak;
        non_skill.id = format!("{}-config", non_skill.id);
        crate::proactive::action_staging::save_proposal(dir.path(), &non_skill).unwrap();

        run_skill_curator_tick(dir.path(), &default_cfg())
            .await
            .unwrap();
        assert!(!dir.path().join("skills").exists());
    }
}
