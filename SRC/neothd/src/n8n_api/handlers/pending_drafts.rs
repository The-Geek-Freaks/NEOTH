//! Read-only pending email-draft adapter for the n8n localhost API.
//!
//! The API uses the checked draft-store reader so external workflow consumers
//! receive a fail-closed result for recognised malformed records, without
//! changing the tolerant legacy `list_drafts` behavior used elsewhere.

use serde::{Deserialize, Serialize};

use super::{parse_body, ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome};
use crate::email::draft::{self, DraftStatus};

/// `/api/email/drafts/pending` request. `min_age_secs` is an inclusive lower
/// age bound; omitted means all currently pending drafts.
#[derive(Clone, Debug, Deserialize)]
pub struct PendingDraftsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub min_age_secs: Option<u64>,
}

/// Minimal reminder metadata. Raw recipient address, brief, signature, and
/// grounded snippets intentionally remain in the local draft store.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingDraftSummary {
    pub id: String,
    pub subject: String,
    pub recipient_display_name: String,
    pub status: String,
    pub generated_ts_unix: i64,
}

/// Response from `/api/email/drafts/pending`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingDraftsResponse {
    pub pending: Vec<PendingDraftSummary>,
    /// Count after status and age filtering, before `limit` truncation.
    pub total: usize,
}

fn bounded_limit(request: &PendingDraftsRequest) -> usize {
    request.limit.unwrap_or(20).min(100)
}

fn draft_age_secs(generated_ts_unix: i64, now_unix: i64) -> u64 {
    if now_unix <= generated_ts_unix {
        0
    } else {
        now_unix.saturating_sub(generated_ts_unix) as u64
    }
}

fn read_pending_drafts_at(
    home: &std::path::Path,
    limit: usize,
    min_age_secs: u64,
    now_unix: i64,
) -> Result<PendingDraftsResponse, HandlerOutcome> {
    let drafts = draft::list_drafts_checked(home, Some(DraftStatus::Pending)).map_err(|error| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("pending email draft store read failed: {error}"),
            "inspect the email draft store under ~/.neoth/email_drafts; recognised corrupt records are not skipped",
        )
    })?;
    let filtered: Vec<_> = drafts
        .into_iter()
        .filter(|draft| draft_age_secs(draft.generated_ts_unix, now_unix) >= min_age_secs)
        .collect();
    let total = filtered.len();
    let pending = filtered
        .into_iter()
        .take(limit)
        .map(|draft| PendingDraftSummary {
            id: draft.id,
            subject: draft.subject,
            recipient_display_name: draft.recipient_display_name,
            status: draft.status.as_str().to_owned(),
            generated_ts_unix: draft.generated_ts_unix,
        })
        .collect();
    Ok(PendingDraftsResponse { pending, total })
}

/// Return pending email-draft reminder metadata in deterministic draft-id
/// order. The handler neither creates the draft directory nor sends email;
/// the server still appends its ordinary request-audit WAL frame.
pub fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: PendingDraftsRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let response = match read_pending_drafts_at(
        &state.home,
        bounded_limit(&request),
        request.min_age_secs.unwrap_or(0),
        crate::time::now_unix_i64(),
    ) {
        Ok(response) => response,
        Err(outcome) => return outcome,
    };
    match serde_json::to_value(response) {
        Ok(body) => HandlerOutcome::ok_json(body),
        Err(error) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("pending email draft response serialisation failed: {error}"),
            "retry after checking the pending draft metadata",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::draft::{build_draft, save_draft, DraftContextSnippet, SalutationLocale};

    fn pending_draft(timestamp: i64) -> crate::email::draft::EmailDraft {
        build_draft(
            format!("recipient-{timestamp}@example.test"),
            format!("Recipient {timestamp}"),
            format!("Subject {timestamp}"),
            "private brief",
            SalutationLocale::EnglishCasual,
            "private signature",
            vec![DraftContextSnippet {
                source_label: "private source".to_owned(),
                excerpt: "private excerpt".to_owned(),
            }],
            timestamp,
        )
    }

    #[test]
    fn pending_drafts_default_cap_zero_and_metadata_only() {
        let home = tempfile::tempdir().unwrap();
        for timestamp in 1_000..1_101 {
            save_draft(home.path(), &pending_draft(timestamp)).unwrap();
        }
        let default = read_pending_drafts_at(home.path(), 20, 0, 2_000).unwrap();
        let capped = read_pending_drafts_at(
            home.path(),
            bounded_limit(&PendingDraftsRequest {
                limit: Some(999),
                min_age_secs: None,
            }),
            0,
            2_000,
        )
        .unwrap();
        let zero = read_pending_drafts_at(home.path(), 0, 0, 2_000).unwrap();
        assert_eq!(default.total, 101);
        assert_eq!(default.pending.len(), 20);
        assert_eq!(capped.pending.len(), 100);
        assert_eq!(zero.total, 101);
        assert!(zero.pending.is_empty());

        let value = serde_json::to_value(default).unwrap();
        for field in ["to", "brief", "signature", "context_snippets", "operator_note"] {
            assert!(value["pending"][0].get(field).is_none(), "unexpected field {field}");
        }
    }

    #[test]
    fn pending_drafts_status_age_and_future_rows_are_filtered() {
        let home = tempfile::tempdir().unwrap();
        let old = pending_draft(100);
        let mut reviewed = pending_draft(200);
        let mut sent = pending_draft(300);
        let mut discarded = pending_draft(350);
        let recent = pending_draft(400);
        let future = pending_draft(700);
        reviewed.status = DraftStatus::Reviewed;
        sent.status = DraftStatus::Sent;
        discarded.status = DraftStatus::Discarded;
        for draft in [&future, &recent, &discarded, &sent, &reviewed, &old] {
            save_draft(home.path(), draft).unwrap();
        }

        let response = read_pending_drafts_at(home.path(), 20, 200, 600).unwrap();
        assert_eq!(response.total, 2);
        assert_eq!(
            response.pending.iter().map(|draft| draft.id.as_str()).collect::<Vec<_>>(),
            vec![old.id.as_str(), recent.id.as_str()]
        );
        assert!(response.pending.iter().all(|draft| draft.status == "pending"));
    }

    #[test]
    fn pending_drafts_request_rejects_wrong_types() {
        let request: PendingDraftsRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(bounded_limit(&request), 20);
        assert_eq!(
            bounded_limit(&PendingDraftsRequest {
                limit: Some(999),
                min_age_secs: None,
            }),
            100
        );
        assert!(parse_body::<PendingDraftsRequest>(br#"{"limit":"20"}"#).is_err());
        assert!(parse_body::<PendingDraftsRequest>(br#"{"min_age_secs":-1}"#).is_err());
    }
}
