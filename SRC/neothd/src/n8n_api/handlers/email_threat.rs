//! Local triage of a concrete submitted email, without mailbox or delivery effects.

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::email::workflow_triage::{WorkflowTriageRequest, triage_workflow_at, validate_request};

pub(super) fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: WorkflowTriageRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    if validate_request(&request).is_err() {
        return invalid_request();
    }
    let received_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            return HandlerOutcome::error(
                ApiErrorCode::StoreUnavailable,
                "email_threat_clock_unavailable",
                "check the instance clock before recording email triage",
            );
        }
    };
    match triage_workflow_at(&state.home, request, received_unix) {
        Ok(result) => HandlerOutcome::ok_json(serde_json::json!({
            "coverage": "submitted_text_and_filenames_only",
            "result": result,
        })),
        Err(_) => HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "email_threat_record_unavailable",
            "inspect the instance quarantine store locally; no mailbox, delivery or vault action was performed",
        ),
    }
}

fn invalid_request() -> HandlerOutcome {
    HandlerOutcome::error(
        ApiErrorCode::BadRequest,
        "email_threat_request_invalid",
        "supply a source key, message key, sender and bounded email text; do not include credentials or binary attachments",
    )
}
