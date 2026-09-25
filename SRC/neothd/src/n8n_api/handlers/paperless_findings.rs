//! Read only the instance's recorded Paperless threat metadata.

use serde::Deserialize;

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecentRequest {
    since_unix: u64,
    #[serde(default)]
    limit: Option<usize>,
}

pub(super) async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: RecentRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let limit = request.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            "paperless_findings_request_invalid",
            "supply since_unix and a limit from 1 to 100",
        );
    }
    match crate::paperless::findings::recent_at(&state.home, request.since_unix, limit) {
        Ok(result) => HandlerOutcome::ok_json(serde_json::json!({
            "coverage": "recorded_quarantines_only",
            "since_unix": request.since_unix,
            "findings": result.findings,
            "total": result.total,
            "truncated": result.truncated,
        })),
        Err(_) => HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "paperless_findings_store_unavailable",
            "inspect the instance findings store locally; incomplete or corrupt evidence is not reported as an empty result",
        ),
    }
}
