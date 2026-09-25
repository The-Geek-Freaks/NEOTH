//! Account-consented CalDAV agenda egress for the authenticated n8n API.

use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;

use super::calendar_agenda::{AgendaProjection, project_local_day_agenda};
use super::{ApiErrorCode, ApiRequestCtx, ApiState, HandlerOutcome, parse_body};
use crate::email::calendar::CalendarEvent;
use crate::tools::caldav_account::{self, CaldavAccount};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgendaRequest {
    timezone: String,
    day: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[async_trait]
trait AgendaReader: Sync {
    async fn read(&self, account: &CaldavAccount) -> anyhow::Result<Vec<CalendarEvent>>;
}

struct CaldavReader;

#[async_trait]
impl AgendaReader for CaldavReader {
    async fn read(&self, account: &CaldavAccount) -> anyhow::Result<Vec<CalendarEvent>> {
        crate::tools::caldav_calendar::list_supported_events_against(
            &account.url,
            &account.username,
            account.password.expose(),
        )
        .await
    }
}

async fn read_at(
    home: &Path,
    request: &AgendaRequest,
    reader: &impl AgendaReader,
) -> Result<AgendaProjection, HandlerOutcome> {
    let limit = request.limit.unwrap_or(20);
    // Validate the complete request before credentials, grant reads or egress.
    project_local_day_agenda(&[], &request.timezone, &request.day, limit).map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            "calendar_agenda_request_invalid",
            "supply a valid IANA timezone, YYYY-MM-DD day and limit from 1 to 100",
        )
    })?;
    let snapshot = caldav_account::resolve_at(home, false).map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "calendar_account_unavailable",
            "configure the CalDAV account in this NEOTH instance; environment fallback is disabled for workflows",
        )
    })?;
    let account = caldav_account::require_at(home, &snapshot, false).map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            "calendar_read_access_not_granted",
            "inspect or grant access with neoth calendar read-access for this instance and account",
        )
    })?;
    // The transport receives only the freshly checked account. Its errors can
    // contain a private endpoint, so HTTP responses use fixed diagnostics.
    let events = reader.read(&account).await.map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            "calendar_agenda_read_failed_or_unsupported",
            "check CalDAV availability and supported event times; recurring, floating or TZID events are not silently omitted",
        )
    })?;
    project_local_day_agenda(&events, &request.timezone, &request.day, limit).map_err(|_| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            "calendar_agenda_projection_unsupported",
            "the response cannot be interpreted as a complete supported local-day agenda",
        )
    })
}

pub(super) async fn handle(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let request: AgendaRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(error) => return error,
    };
    match read_at(&state.home, &request, &CaldavReader).await {
        Ok(agenda) => HandlerOutcome::ok_json(serde_json::json!(agenda)),
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountedReader {
        calls: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl AgendaReader for CountedReader {
        async fn read(&self, account: &CaldavAccount) -> anyhow::Result<Vec<CalendarEvent>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(account.url, "https://calendar.example.test/collection/");
            if self.fail {
                anyhow::bail!("private URL and password must not reach the HTTP response");
            }
            Ok(vec![CalendarEvent {
                calendar_id: "private-calendar".into(),
                event_id: "private-event".into(),
                summary: "Meeting".into(),
                description: "private-notes".into(),
                location: "Office".into(),
                start_rfc3339: "2026-09-25T08:00:00Z".into(),
                end_rfc3339: "2026-09-25T09:00:00Z".into(),
                attendees: vec!["private-attendee".into()],
            }])
        }
    }

    fn request() -> AgendaRequest {
        AgendaRequest {
            timezone: "Europe/Berlin".into(),
            day: "2026-09-25".into(),
            limit: Some(20),
        }
    }

    fn configure(home: &Path) -> CaldavAccount {
        std::fs::write(home.join("freedom.yaml"), "secrets_backend: file\n").unwrap();
        std::fs::write(
            home.join("credentials.yaml"),
            "caldav_url: https://calendar.example.test/collection/\ncaldav_username: operator\ncaldav_password: fixture-password\n",
        )
        .unwrap();
        caldav_account::resolve_at(home, false).unwrap()
    }

    #[tokio::test]
    async fn missing_grant_and_invalid_request_make_zero_transport_calls() {
        let home = tempfile::tempdir().unwrap();
        configure(home.path());
        let reader = CountedReader {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        let error = read_at(home.path(), &request(), &reader).await.unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::PermissionDenied));
        let mut invalid = request();
        invalid.limit = Some(101);
        let error = read_at(home.path(), &invalid, &reader).await.unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::BadRequest));
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn granted_account_reads_once_and_revocation_denies_next_request() {
        let home = tempfile::tempdir().unwrap();
        let account = configure(home.path());
        caldav_account::grant_at(home.path(), &account).unwrap();
        let reader = CountedReader {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        let result = read_at(home.path(), &request(), &reader).await.unwrap();
        assert_eq!(result.events.len(), 1);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("private-"));
        assert!(!json.contains("fixture-password"));
        assert!(!json.contains("example.test"));
        caldav_account::revoke_at(home.path()).unwrap();
        let error = read_at(home.path(), &request(), &reader).await.unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::PermissionDenied));
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transport_errors_are_redacted_and_missing_account_is_unavailable() {
        let home = tempfile::tempdir().unwrap();
        let reader = CountedReader {
            calls: AtomicUsize::new(0),
            fail: true,
        };
        let error = read_at(home.path(), &request(), &reader).await.unwrap_err();
        assert_eq!(error.error_code(), Some(ApiErrorCode::StoreUnavailable));
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        let account = configure(home.path());
        caldav_account::grant_at(home.path(), &account).unwrap();
        let error = read_at(home.path(), &request(), &reader).await.unwrap_err();
        match error {
            HandlerOutcome::Err {
                code,
                message,
                hint,
            } => {
                assert_eq!(code, ApiErrorCode::UpstreamError);
                assert_eq!(message, "calendar_agenda_read_failed_or_unsupported");
                assert!(!hint.contains("private URL"));
            }
            _ => panic!("transport failure must be an error"),
        }
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    }
}
