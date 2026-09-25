//! Read-only pending-proposal adapter for the n8n localhost API.
//!
//! Proposal staging is a file store. [`crate::proactive::action_staging::list_proposals`]
//! opens it without creating it; a missing store is therefore an empty result,
//! while recognised corrupt proposal records remain a structured failure.

use serde::{Deserialize, Serialize};

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::proactive::action_staging::{self, ProposalStatus};

/// `/api/proactive/proposals/pending` request. `min_age_secs` is an inclusive
/// lower age bound for reminder workflows; omitted means all pending proposals.
#[derive(Clone, Debug, Deserialize)]
pub struct PendingProposalsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub min_age_secs: Option<u64>,
}

/// Metadata sufficient for an operator review reminder. Deliberately excludes
/// rationale, draft YAML, and operator notes: those remain available through
/// the local proposal store/CLI rather than the workflow webhook response.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingProposalSummary {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub generated_ts_unix: i64,
    pub status: String,
}

/// Response from `/api/proactive/proposals/pending`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingProposalsResponse {
    pub pending: Vec<PendingProposalSummary>,
    /// Count after status and age filtering, before `limit` truncation.
    pub total: usize,
}

fn proposal_age_secs(generated_ts_unix: i64, now_unix: i64) -> u64 {
    if now_unix <= generated_ts_unix {
        0
    } else {
        now_unix.saturating_sub(generated_ts_unix) as u64
    }
}

fn bounded_limit(request: &PendingProposalsRequest) -> usize {
    request.limit.unwrap_or(20).min(100)
}

fn read_pending_proposals_at(
    home: &std::path::Path,
    limit: usize,
    min_age_secs: u64,
    now_unix: i64,
) -> Result<PendingProposalsResponse, HandlerOutcome> {
    let proposals = action_staging::list_proposals(home, Some(ProposalStatus::Pending)).map_err(|error| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("pending proposal store read failed: {error}"),
            "inspect the proposal store under ~/.neoth/proposals; recognised corrupt records are not skipped",
        )
    })?;

    let filtered: Vec<_> = proposals
        .into_iter()
        .filter(|proposal| proposal_age_secs(proposal.generated_ts_unix, now_unix) >= min_age_secs)
        .collect();
    let total = filtered.len();
    let pending = filtered
        .into_iter()
        .take(limit)
        .map(|proposal| PendingProposalSummary {
            id: proposal.id,
            kind: proposal.kind.as_str().to_owned(),
            title: proposal.title,
            generated_ts_unix: proposal.generated_ts_unix,
            status: proposal.status.as_str().to_owned(),
        })
        .collect();

    Ok(PendingProposalsResponse { pending, total })
}

/// Return pending staged-action summaries in the file store's deterministic id
/// order. This is read-only: it creates no proposal directory or SQLite
/// database and makes no provider request or delivery. The server still emits
/// its normal request-audit WAL frame around every API call.
pub fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: PendingProposalsRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let limit = bounded_limit(&request);
    let min_age_secs = request.min_age_secs.unwrap_or(0);
    let response = match read_pending_proposals_at(
        &state.home,
        limit,
        min_age_secs,
        crate::time::now_unix_i64(),
    ) {
        Ok(response) => response,
        Err(outcome) => return outcome,
    };
    match serde_json::to_value(response) {
        Ok(body) => HandlerOutcome::ok_json(body),
        Err(error) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("pending proposal response serialisation failed: {error}"),
            "retry after checking the pending proposal metadata",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proactive::action_staging::{ProposalKind, ProposedAction, save_proposal};

    fn proposal(id: &str, status: ProposalStatus, generated_ts_unix: i64) -> ProposedAction {
        ProposedAction {
            id: id.to_owned(),
            kind: ProposalKind::CronJob,
            title: format!("title-{id}"),
            rationale: "private rationale".to_owned(),
            draft_yaml: "private: draft".to_owned(),
            generated_ts_unix,
            status,
            operator_note: "private note".to_owned(),
        }
    }

    #[test]
    fn pending_proposals_default_cap_zero_and_metadata_only() {
        let home = tempfile::tempdir().unwrap();
        for index in 0..101 {
            let id = format!("{}-cron_job-{index:08x}", 1_000 + index);
            save_proposal(
                home.path(),
                &proposal(&id, ProposalStatus::Pending, 1_000 + index),
            )
            .unwrap();
        }

        let default = read_pending_proposals_at(home.path(), 20, 0, 2_000).unwrap();
        let capped = read_pending_proposals_at(
            home.path(),
            bounded_limit(&PendingProposalsRequest {
                limit: Some(999),
                min_age_secs: None,
            }),
            0,
            2_000,
        )
        .unwrap();
        let zero = read_pending_proposals_at(home.path(), 0, 0, 2_000).unwrap();
        assert_eq!(default.total, 101);
        assert_eq!(default.pending.len(), 20);
        assert_eq!(capped.pending.len(), 100);
        assert_eq!(zero.total, 101);
        assert!(zero.pending.is_empty());

        let value = serde_json::to_value(&default).unwrap();
        assert!(value["pending"][0].get("draft_yaml").is_none());
        assert!(value["pending"][0].get("rationale").is_none());
        assert!(value["pending"][0].get("operator_note").is_none());
    }

    #[test]
    fn pending_proposals_filter_status_age_and_keep_id_order() {
        let home = tempfile::tempdir().unwrap();
        save_proposal(
            home.path(),
            &proposal("100-cron_job-00000001", ProposalStatus::Pending, 100),
        )
        .unwrap();
        save_proposal(
            home.path(),
            &proposal("200-cron_job-00000002", ProposalStatus::Approved, 200),
        )
        .unwrap();
        save_proposal(
            home.path(),
            &proposal("300-cron_job-00000003", ProposalStatus::Rejected, 300),
        )
        .unwrap();
        save_proposal(
            home.path(),
            &proposal("400-cron_job-00000004", ProposalStatus::Pending, 400),
        )
        .unwrap();
        save_proposal(
            home.path(),
            &proposal("600-cron_job-00000005", ProposalStatus::Pending, 600),
        )
        .unwrap();
        save_proposal(
            home.path(),
            &proposal("700-cron_job-00000006", ProposalStatus::Pending, 700),
        )
        .unwrap();

        let response = read_pending_proposals_at(home.path(), 20, 200, 600).unwrap();
        assert_eq!(response.total, 2);
        assert_eq!(
            response
                .pending
                .iter()
                .map(|proposal| proposal.id.as_str())
                .collect::<Vec<_>>(),
            vec!["100-cron_job-00000001", "400-cron_job-00000004"]
        );
        assert!(
            response
                .pending
                .iter()
                .all(|proposal| proposal.status == "pending")
        );
    }

    #[test]
    fn pending_proposals_missing_store_is_empty_without_creation() {
        let home = tempfile::tempdir().unwrap();
        let proposals = home.path().join("proposals");
        let response = read_pending_proposals_at(home.path(), 20, 0, 1_000).unwrap();
        assert_eq!(response.total, 0);
        assert!(response.pending.is_empty());
        assert!(!proposals.exists());
    }

    #[test]
    fn pending_proposals_recognised_corruption_is_a_structured_error() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("proposals");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("100-cron_job-00000001.json"), b"not json").unwrap();

        let error = read_pending_proposals_at(home.path(), 20, 0, 1_000).unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::UpstreamError));
        match error {
            HandlerOutcome::Err { message, .. } => {
                assert!(message.contains("proposal store read failed"))
            }
            HandlerOutcome::Ok { .. } => panic!("corrupt recognised proposal must fail closed"),
        }
    }

    #[test]
    fn pending_proposals_request_rejects_wrong_types() {
        let request: PendingProposalsRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(request.limit, None);
        assert_eq!(request.min_age_secs, None);
        assert_eq!(bounded_limit(&request), 20);
        assert_eq!(
            bounded_limit(&PendingProposalsRequest {
                limit: Some(999),
                min_age_secs: None,
            }),
            100
        );
        assert!(parse_body::<PendingProposalsRequest>(br#"{"limit":"20"}"#).is_err());
        assert!(parse_body::<PendingProposalsRequest>(br#"{"min_age_secs":-1}"#).is_err());
    }
}
