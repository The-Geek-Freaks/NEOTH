//! Bounded keyword lookup in this instance's configured local Paperless notes.

use std::path::PathBuf;

use serde::Deserialize;

use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsultRequest {
    question: String,
    #[serde(default)]
    limit: Option<usize>,
}

pub(super) async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: ConsultRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    let limit = request.limit.unwrap_or(5);
    if request.question.trim().is_empty()
        || request.question.len() > 4096
        || !(1..=20).contains(&limit)
    {
        return invalid_request();
    }
    // Capture the accepted configuration once; the request cannot select a
    // vault, a subdirectory or an ambient-home fallback.
    let config = state.reload_controller.latest();
    let Some(vault) = config.obsidian_vault.as_ref().filter(|path| !path.trim().is_empty()) else {
        return HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "paperless_consult_vault_not_configured",
            "configure this instance's Obsidian vault before querying local Paperless notes",
        );
    };
    let vault = PathBuf::from(vault);
    let subdir = config.obsidian_subdir.clone().unwrap_or_else(|| "NEOTH".to_owned());
    let result = tokio::task::spawn_blocking(move || {
        crate::paperless::consult::consult_bounded(&vault, &subdir, &request.question, limit)
    })
    .await;
    match result {
        Ok(Ok(result)) => {
            let matches: Vec<_> = result.matches.into_iter().map(|item| {
                serde_json::json!({
                    "filename": item.filename,
                    "score": item.score,
                    "excerpt": item.excerpt,
                })
            }).collect();
            HandlerOutcome::ok_json(serde_json::json!({
                "coverage": "local_paperless_notes_keyword_lookup",
                "matches": matches,
                "query_tokens": result.query_tokens,
                "scanned": result.scanned,
            }))
        }
        _ => HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "paperless_consult_unavailable_or_limit_exceeded",
            "inspect the configured local Paperless notes; unreadable files and scan limits are not reported as an empty result",
        ),
    }
}

fn invalid_request() -> HandlerOutcome {
    HandlerOutcome::error(
        ApiErrorCode::BadRequest,
        "paperless_consult_request_invalid",
        "supply a nonempty question up to 4096 bytes and a limit from 1 to 20",
    )
}
