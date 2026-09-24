//! ADOPT31-D6 — truthful specialist-candidate advice from local usage rollups.
//!
//! The usage log establishes only a closed workflow class, observed call
//! volume, and reported or unpriced cost. Provider completion is not semantic
//! correctness. The other checklist facts therefore stay explicit operator
//! evidence and an incomplete assessment can never yield a candidate.

use std::path::Path;

use serde::Deserialize;

use crate::daemon::usage_log::UsageRollup;
use crate::proactive::ProactiveItem;

/// Conservative local policy for the daily proactive observation. Callers of
/// [`analyze`] may select a different threshold explicitly.
pub const DEFAULT_MINIMUM_CALL_COUNT: u64 = 100;
pub const ASSESSMENT_FILE_NAME: &str = "specialist_assessments.json";
const ASSESSMENT_SCHEMA_VERSION: u8 = 1;
const MAX_ASSESSMENT_FILE_BYTES: u64 = 64 * 1024;
const MAX_ASSESSMENT_ROWS: usize = 64;
const PROACTIVE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// Operator evidence for a checklist fact that the usage log cannot prove.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistEvidence {
    Confirmed,
    Unknown,
    Rejected,
}

/// The article checklist, kept explicit in advisor output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecklistCriterion {
    HighVolume,
    OutcomeCheckable,
    ExpertAgreement,
    ModelSucceedsSometimes,
    NotLuckyGuess,
    MultiStepCommitted,
    OwnToolsAndSchemas,
    AsymmetricErrorCosts,
    DataStaysLocal,
}

impl ChecklistCriterion {
    fn label(self) -> &'static str {
        match self {
            Self::HighVolume => "hohes beobachtetes Volumen",
            Self::OutcomeCheckable => "regel-, test- oder rubric-pruefbares Ergebnis",
            Self::ExpertAgreement => "Expertenkonsens zum korrekten Ergebnis",
            Self::ModelSucceedsSometimes => "belegter semantischer Modellerfolg",
            Self::NotLuckyGuess => "kein plausibler Glueckstreffer",
            Self::MultiStepCommitted => "mehrstufiger Tool-/Entscheidungsablauf",
            Self::OwnToolsAndSchemas => "eigene Tools und Schemata",
            Self::AsymmetricErrorCosts => "unterschiedliche Fehlerkosten",
            Self::DataStaysLocal => "lokale Datenresidenz",
        }
    }
}

/// Explicit operator assessment for one closed usage-log workflow label. D6
/// reads it only from its versioned local assessment file and never infers it
/// from provider success.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowAssessment {
    pub workflow: String,
    pub outcome_checkable: ChecklistEvidence,
    pub expert_agreement: ChecklistEvidence,
    pub model_succeeds_sometimes: ChecklistEvidence,
    pub not_lucky_guess: ChecklistEvidence,
    pub multi_step_committed: ChecklistEvidence,
    pub owns_tools_and_schemas: ChecklistEvidence,
    pub asymmetric_error_costs: ChecklistEvidence,
    pub data_stays_local: ChecklistEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessmentFile {
    schema_version: u8,
    assessments: Vec<WorkflowAssessment>,
}

/// Read the strictly bounded local operator evidence file. A missing file is
/// normal and means every non-log criterion remains unknown. Every malformed
/// or ambiguous file is rejected as a whole, so it cannot accidentally make a
/// workflow eligible.
pub fn load_operator_assessments(home: &Path) -> Result<Vec<WorkflowAssessment>, String> {
    let path = home.join(ASSESSMENT_FILE_NAME);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    };
    if !metadata.is_file() || metadata.len() > MAX_ASSESSMENT_FILE_BYTES {
        return Err(format!(
            "{} must be a regular file no larger than {MAX_ASSESSMENT_FILE_BYTES} bytes",
            path.display()
        ));
    }
    use std::io::Read;
    let file =
        std::fs::File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut raw = Vec::new();
    file.take(MAX_ASSESSMENT_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if raw.len() as u64 > MAX_ASSESSMENT_FILE_BYTES {
        return Err(format!(
            "{} exceeds the {MAX_ASSESSMENT_FILE_BYTES}-byte assessment limit",
            path.display()
        ));
    }
    let file: AssessmentFile = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if file.schema_version != ASSESSMENT_SCHEMA_VERSION {
        return Err(format!(
            "{} has unsupported schema_version {}; expected {ASSESSMENT_SCHEMA_VERSION}",
            path.display(),
            file.schema_version
        ));
    }
    if file.assessments.len() > MAX_ASSESSMENT_ROWS {
        return Err(format!(
            "{} has {} assessments; maximum is {MAX_ASSESSMENT_ROWS}",
            path.display(),
            file.assessments.len()
        ));
    }
    let mut workflows = std::collections::HashSet::new();
    for assessment in &file.assessments {
        if !is_closed_workflow_label(&assessment.workflow) {
            return Err(format!(
                "{} has unknown workflow label `{}`",
                path.display(),
                assessment.workflow
            ));
        }
        if !workflows.insert(&assessment.workflow) {
            return Err(format!(
                "{} has duplicate workflow assessment `{}`",
                path.display(),
                assessment.workflow
            ));
        }
    }
    Ok(file.assessments)
}

fn is_closed_workflow_label(workflow: &str) -> bool {
    matches!(
        workflow,
        "chat_turn"
            | "chat_post_reply"
            | "deep_research"
            | "session_naming"
            | "background_session"
            | "council_deliberation"
            | "mcp_agent_loop"
            | "n8n_provider_call"
            | "cluster_delegated"
            | "history_compaction"
            | "teacher_escalation"
            | "refusal_recovery"
            | "scheduled_maintenance"
    )
}

/// D7's routing-relevant operator evidence for one explicitly named closed
/// workflow. It is a copy of the strict D6 row, so callers cannot infer facts
/// from usage, provider success, or G02 notifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiabilityEvidence {
    pub outcome_checkable: ChecklistEvidence,
    pub expert_agreement: ChecklistEvidence,
    pub model_succeeds_sometimes: ChecklistEvidence,
    pub not_lucky_guess: ChecklistEvidence,
    pub multi_step_committed: ChecklistEvidence,
    pub owns_tools_and_schemas: ChecklistEvidence,
    pub asymmetric_error_costs: ChecklistEvidence,
    pub data_stays_local: ChecklistEvidence,
}

impl VerifiabilityEvidence {
    /// A human handoff is reserved for an explicit rejection of the two facts
    /// that establish whether a result can be verified at all. Rejections of
    /// specialist/residency facts are not a claim that the workflow is
    /// unverifiable.
    pub fn explicitly_unverifiable(self) -> bool {
        matches!(self.outcome_checkable, ChecklistEvidence::Rejected)
            || matches!(self.expert_agreement, ChecklistEvidence::Rejected)
    }

    /// The minimum evidence for the rare-workflow frontier direction. D7 does
    /// not require a specialist-only checklist (tools, residency, or committed
    /// multi-step execution) before a rare outcome can be verified.
    pub fn verifiable(self) -> bool {
        matches!(self.outcome_checkable, ChecklistEvidence::Confirmed)
            && matches!(self.expert_agreement, ChecklistEvidence::Confirmed)
    }

    /// The existing D6 specialist threshold remains intentionally stronger.
    pub fn fully_specialist_eligible(self) -> bool {
        [
            self.outcome_checkable,
            self.expert_agreement,
            self.model_succeeds_sometimes,
            self.not_lucky_guess,
            self.multi_step_committed,
            self.owns_tools_and_schemas,
            self.asymmetric_error_costs,
            self.data_stays_local,
        ]
        .into_iter()
        .all(|evidence| matches!(evidence, ChecklistEvidence::Confirmed))
    }
}

/// Return D7 evidence only for one unique D6 closed-workflow assessment.
/// Missing, duplicate, or unclassified input deliberately becomes unavailable
/// rather than a route decision. The file loader already rejects duplicates;
/// retaining this check keeps direct callers fail-closed too.
pub fn verifiability_evidence_for_workflow(
    assessments: &[WorkflowAssessment],
    workflow: &str,
) -> Option<VerifiabilityEvidence> {
    if !is_closed_workflow_label(workflow) {
        return None;
    }
    let matching = assessments
        .iter()
        .filter(|assessment| assessment.workflow == workflow)
        .collect::<Vec<_>>();
    let [assessment] = matching.as_slice() else {
        return None;
    };
    Some(VerifiabilityEvidence {
        outcome_checkable: assessment.outcome_checkable,
        expert_agreement: assessment.expert_agreement,
        model_succeeds_sometimes: assessment.model_succeeds_sometimes,
        not_lucky_guess: assessment.not_lucky_guess,
        multi_step_committed: assessment.multi_step_committed,
        owns_tools_and_schemas: assessment.owns_tools_and_schemas,
        asymmetric_error_costs: assessment.asymmetric_error_costs,
        data_stays_local: assessment.data_stays_local,
    })
}

/// Public closed-label guard shared by request-bound consumers. Workflow names
/// are never inferred from prompt text or later usage attribution.
pub fn is_closed_workflow(workflow: &str) -> bool {
    is_closed_workflow_label(workflow)
}
/// The only conclusion D6 may make about a workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialistVerdict {
    Candidate,
    InsufficientEvidence,
    NotCandidate,
}

/// Operator-readable advice for one closed workflow class.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowAdvice {
    pub workflow: String,
    pub call_count: u64,
    pub known_cost_usd: f64,
    pub unknown_cost_count: u64,
    pub meets_minimum_volume: bool,
    pub verdict: SpecialistVerdict,
    pub missing_criteria: Vec<ChecklistCriterion>,
    pub rejected_criteria: Vec<ChecklistCriterion>,
}

/// Deterministically ordered D6 output. It contains no provider, prompt, or
/// routing decision and has no side effects.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpecialistAdvisorReport {
    pub workflows: Vec<WorkflowAdvice>,
}

/// Apply the nine-point checklist to already-aggregated local usage data.
///
/// `minimum_call_count` is deliberately a caller-provided policy rather than
/// an implied property of a workflow label. Exact duplicate assessments are
/// treated as unavailable evidence, preventing an ambiguous input from making
/// a positive recommendation.
pub fn analyze(
    rollup: &UsageRollup,
    minimum_call_count: u64,
    assessments: &[WorkflowAssessment],
) -> SpecialistAdvisorReport {
    let mut workflows = rollup
        .per_workflow
        .iter()
        .filter(|row| row.call_count > 0)
        .map(|row| {
            let workflow = row.workflow.as_str().to_string();
            let matching = assessments
                .iter()
                .filter(|assessment| assessment.workflow == workflow)
                .collect::<Vec<_>>();
            let assessment = match matching.as_slice() {
                [assessment] => Some(*assessment),
                _ => None,
            };
            let meets_minimum_volume = row.call_count >= minimum_call_count;
            let mut missing_criteria = Vec::new();
            let mut rejected_criteria = Vec::new();

            if !meets_minimum_volume || workflow == "unclassified" {
                rejected_criteria.push(ChecklistCriterion::HighVolume);
            }
            for (criterion, evidence) in assessment_evidence(assessment) {
                match evidence {
                    ChecklistEvidence::Confirmed => {}
                    ChecklistEvidence::Unknown => missing_criteria.push(criterion),
                    ChecklistEvidence::Rejected => rejected_criteria.push(criterion),
                }
            }

            let verdict = if !rejected_criteria.is_empty() {
                SpecialistVerdict::NotCandidate
            } else if !missing_criteria.is_empty() {
                SpecialistVerdict::InsufficientEvidence
            } else {
                SpecialistVerdict::Candidate
            };

            WorkflowAdvice {
                workflow,
                call_count: row.call_count,
                known_cost_usd: row.known_cost_usd,
                unknown_cost_count: row.unknown_cost_count,
                meets_minimum_volume,
                verdict,
                missing_criteria,
                rejected_criteria,
            }
        })
        .collect::<Vec<_>>();
    workflows.sort_by(|left, right| {
        right
            .call_count
            .cmp(&left.call_count)
            .then_with(|| left.workflow.cmp(&right.workflow))
    });
    SpecialistAdvisorReport { workflows }
}

fn assessment_evidence(
    assessment: Option<&WorkflowAssessment>,
) -> [(ChecklistCriterion, ChecklistEvidence); 8] {
    let unknown = ChecklistEvidence::Unknown;
    let Some(assessment) = assessment else {
        return [
            (ChecklistCriterion::OutcomeCheckable, unknown),
            (ChecklistCriterion::ExpertAgreement, unknown),
            (ChecklistCriterion::ModelSucceedsSometimes, unknown),
            (ChecklistCriterion::NotLuckyGuess, unknown),
            (ChecklistCriterion::MultiStepCommitted, unknown),
            (ChecklistCriterion::OwnToolsAndSchemas, unknown),
            (ChecklistCriterion::AsymmetricErrorCosts, unknown),
            (ChecklistCriterion::DataStaysLocal, unknown),
        ];
    };
    [
        (
            ChecklistCriterion::OutcomeCheckable,
            assessment.outcome_checkable,
        ),
        (
            ChecklistCriterion::ExpertAgreement,
            assessment.expert_agreement,
        ),
        (
            ChecklistCriterion::ModelSucceedsSometimes,
            assessment.model_succeeds_sometimes,
        ),
        (
            ChecklistCriterion::NotLuckyGuess,
            assessment.not_lucky_guess,
        ),
        (
            ChecklistCriterion::MultiStepCommitted,
            assessment.multi_step_committed,
        ),
        (
            ChecklistCriterion::OwnToolsAndSchemas,
            assessment.owns_tools_and_schemas,
        ),
        (
            ChecklistCriterion::AsymmetricErrorCosts,
            assessment.asymmetric_error_costs,
        ),
        (
            ChecklistCriterion::DataStaysLocal,
            assessment.data_stays_local,
        ),
    ]
}

/// Render at most one bounded proactive request for the highest-ranked
/// workflow whose assessment is still incomplete. The item itself says it is
/// not a candidate and is monthly deduplicated to avoid repeated daily nudges.
pub fn assessment_required_item(
    report: &SpecialistAdvisorReport,
    now_unix: i64,
) -> Option<ProactiveItem> {
    let advice = report.workflows.iter().find(|advice| {
        advice.meets_minimum_volume && advice.verdict == SpecialistVerdict::InsufficientEvidence
    })?;
    let missing = advice
        .missing_criteria
        .iter()
        .map(|criterion| criterion.label())
        .collect::<Vec<_>>()
        .join(", ");
    Some(ProactiveItem {
        priority: 10,
        dedup_key: format!("specialist-advisor:assessment-required:{}", advice.workflow),
        channel: "cli".to_string(),
        account_id: None,
        account_binding: None,
        source: "specialist_advisor".to_string(),
        body: format!(
            "Spezialisierungspruefung fuer `{}`: {} Aufrufe, bekannte Kosten ${:.4}, {} Aufruf(e) ohne Preis. Noch kein Spezialisten-Kandidat: Bitte bewerte {}. Provider-Erfolg zaehlt dabei nicht als fachlicher Modellerfolg.",
            advice.workflow,
            advice.call_count,
            advice.known_cost_usd,
            advice.unknown_cost_count,
            missing,
        ),
        scheduled_for_unix: now_unix,
        is_failure: false,
        expires_unix: now_unix.saturating_add(PROACTIVE_TTL_SECS),
    })
}

/// Render the bounded D6 proactive output: at most one fully evidenced
/// candidate and at most one independent assessment request. Candidate status
/// originates only from the supplied local operator evidence plus this
/// report's observed volume; it has no routing or training effect.
pub fn proactive_items(report: &SpecialistAdvisorReport, now_unix: i64) -> Vec<ProactiveItem> {
    let mut items = Vec::new();
    if let Some(advice) = report
        .workflows
        .iter()
        .find(|advice| advice.verdict == SpecialistVerdict::Candidate)
    {
        items.push(ProactiveItem {
            priority: 50,
            dedup_key: format!("specialist-advisor:candidate:{}", advice.workflow),
            channel: "cli".to_string(),
            account_id: None,
            account_binding: None,
            source: "specialist_advisor".to_string(),
            body: format!(
                "Spezialisierungs-Kandidat `{}`: {} Aufrufe im beobachteten 30-Tage-Fenster, bekannte Kosten ${:.4}, {} Aufruf(e) ohne Preis. Alle acht nicht aus dem Usage-Log ableitbaren Checklistenpunkte sind lokal als bestaetigt hinterlegt. Das ist nur eine Empfehlung; es aendert weder Routing noch Training.",
                advice.workflow,
                advice.call_count,
                advice.known_cost_usd,
                advice.unknown_cost_count,
            ),
            scheduled_for_unix: now_unix,
            is_failure: false,
            expires_unix: now_unix.saturating_add(PROACTIVE_TTL_SECS),
        });
    }
    if let Some(item) = assessment_required_item(report, now_unix) {
        items.push(item);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::usage_log::{PerWorkflowTotals, WorkflowKey};

    fn rollup(calls: u64, ok: u64, known_cost_usd: f64, unknown_cost_count: u64) -> UsageRollup {
        UsageRollup {
            per_workflow: vec![PerWorkflowTotals {
                workflow: WorkflowKey::from_audited(
                    Some("chat_provider_round"),
                    Some("chat"),
                    Some("chat_provider_round"),
                ),
                call_count: calls,
                ok_count: ok,
                known_cost_usd,
                unknown_cost_count,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn confirmed_assessment() -> WorkflowAssessment {
        WorkflowAssessment {
            workflow: "chat_turn".to_string(),
            outcome_checkable: ChecklistEvidence::Confirmed,
            expert_agreement: ChecklistEvidence::Confirmed,
            model_succeeds_sometimes: ChecklistEvidence::Confirmed,
            not_lucky_guess: ChecklistEvidence::Confirmed,
            multi_step_committed: ChecklistEvidence::Confirmed,
            owns_tools_and_schemas: ChecklistEvidence::Confirmed,
            asymmetric_error_costs: ChecklistEvidence::Confirmed,
            data_stays_local: ChecklistEvidence::Confirmed,
        }
    }

    #[test]
    fn unknown_checklist_evidence_never_yields_a_specialist_candidate() {
        let report = analyze(&rollup(200, 200, 12.5, 3), 100, &[]);
        let advice = &report.workflows[0];
        assert_eq!(advice.verdict, SpecialistVerdict::InsufficientEvidence);
        assert_eq!(advice.missing_criteria.len(), 8);
        assert!(
            advice
                .missing_criteria
                .contains(&ChecklistCriterion::OutcomeCheckable)
        );
    }

    #[test]
    fn all_explicit_checklist_evidence_and_observed_volume_yield_candidate() {
        let assessment = confirmed_assessment();
        let report = analyze(&rollup(100, 1, 4.25, 2), 100, &[assessment]);
        let advice = &report.workflows[0];
        assert_eq!(advice.verdict, SpecialistVerdict::Candidate);
        assert_eq!(advice.known_cost_usd, 4.25);
        assert_eq!(advice.unknown_cost_count, 2);
    }

    #[test]
    fn provider_success_is_not_inferred_as_model_quality() {
        let report = analyze(&rollup(100, 100, 0.0, 0), 100, &[]);
        assert_eq!(
            report.workflows[0].verdict,
            SpecialistVerdict::InsufficientEvidence
        );
        assert!(
            report.workflows[0]
                .missing_criteria
                .contains(&ChecklistCriterion::ModelSucceedsSometimes)
        );
    }

    #[test]
    fn unknown_cost_stays_unknown_in_advice() {
        let report = analyze(&rollup(100, 0, 0.0, 7), 100, &[]);
        let item = assessment_required_item(&report, 1_700_000_000).unwrap();
        assert_eq!(report.workflows[0].unknown_cost_count, 7);
        assert!(item.body.contains("7 Aufruf(e) ohne Preis"));
    }

    #[test]
    fn duplicate_assessments_are_not_candidate_evidence() {
        let assessment = confirmed_assessment();
        let report = analyze(
            &rollup(100, 0, 1.0, 0),
            100,
            &[assessment.clone(), assessment],
        );
        assert_eq!(
            report.workflows[0].verdict,
            SpecialistVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn operator_assessment_file_accepts_only_closed_unique_schema_v1_rows() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(ASSESSMENT_FILE_NAME);
        assert!(load_operator_assessments(home.path()).unwrap().is_empty());
        let valid = serde_json::json!({
            "schema_version": 1,
            "assessments": [{
                "workflow": "chat_turn",
                "outcome_checkable": "confirmed",
                "expert_agreement": "confirmed",
                "model_succeeds_sometimes": "confirmed",
                "not_lucky_guess": "confirmed",
                "multi_step_committed": "confirmed",
                "owns_tools_and_schemas": "confirmed",
                "asymmetric_error_costs": "confirmed",
                "data_stays_local": "confirmed"
            }]
        });
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(load_operator_assessments(home.path()).unwrap().len(), 1);

        let mut invalid = Vec::new();
        for label in ["unclassified", "unknown_workflow"] {
            let mut value = valid.clone();
            value["assessments"][0]["workflow"] = label.into();
            invalid.push(value);
        }
        let mut value = valid.clone();
        value["schema_version"] = 2.into();
        invalid.push(value);
        let mut value = valid.clone();
        value["extra"] = true.into();
        invalid.push(value);
        let mut value = valid.clone();
        value["assessments"][0]["outcome_checkable"] = "maybe".into();
        invalid.push(value);
        let mut value = valid.clone();
        value["assessments"][0]["extra"] = true.into();
        invalid.push(value);
        let mut value = valid.clone();
        value["assessments"][0]
            .as_object_mut()
            .unwrap()
            .remove("expert_agreement");
        invalid.push(value);
        let mut value = valid.clone();
        let duplicate = value["assessments"][0].clone();
        value["assessments"].as_array_mut().unwrap().push(duplicate);
        invalid.push(value);
        for value in invalid {
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(load_operator_assessments(home.path()).is_err());
        }
        std::fs::write(&path, vec![b' '; MAX_ASSESSMENT_FILE_BYTES as usize + 1]).unwrap();
        assert!(load_operator_assessments(home.path()).is_err());
    }

    #[test]
    fn proactive_items_surface_a_confirmed_candidate() {
        let report = analyze(&rollup(100, 0, 4.0, 1), 100, &[confirmed_assessment()]);
        let items = proactive_items(&report, 1_700_000_000);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].dedup_key, "specialist-advisor:candidate:chat_turn");
        assert!(items[0].body.contains("30-Tage-Fenster"));
    }

    #[test]
    fn unclassified_usage_never_becomes_a_candidate() {
        let rollup = UsageRollup {
            per_workflow: vec![PerWorkflowTotals {
                call_count: 100,
                ..Default::default()
            }],
            ..Default::default()
        };
        let report = analyze(&rollup, 100, &[]);
        assert_eq!(report.workflows[0].verdict, SpecialistVerdict::NotCandidate);
    }
    #[test]
    fn d7_evidence_requires_one_closed_unique_assessment() {
        let assessment = confirmed_assessment();
        let evidence = verifiability_evidence_for_workflow(&[assessment.clone()], "chat_turn").expect("unique closed row");
        assert_eq!(evidence.outcome_checkable, ChecklistEvidence::Confirmed);
        assert_eq!(evidence.expert_agreement, ChecklistEvidence::Confirmed);
        assert!(verifiability_evidence_for_workflow(&[], "chat_turn").is_none());
        assert!(verifiability_evidence_for_workflow(&[assessment.clone(), assessment], "chat_turn").is_none());
        assert!(verifiability_evidence_for_workflow(&[], "unclassified").is_none());
    }

    #[test]
    fn d7_human_evidence_is_limited_to_outcome_or_expert_rejection() {
        let mut assessment = confirmed_assessment();
        assessment.owns_tools_and_schemas = ChecklistEvidence::Rejected;
        let evidence = verifiability_evidence_for_workflow(&[assessment], "chat_turn").unwrap();
        assert!(evidence.verifiable());
        assert!(!evidence.explicitly_unverifiable());
        assert!(!evidence.fully_specialist_eligible());
    }
}
