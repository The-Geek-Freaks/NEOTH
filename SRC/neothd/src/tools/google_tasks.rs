//! `google_tasks` — TD-02. Google Tasks adapter with OAuth-refresh:
//! list / create / close over `tasks.googleapis.com/tasks/v1`.
//!
//! Same shape as the sibling [`super::todoist`] adapter: every public fn
//! delegates to an `_against(base, …)` seam so the wiremock tests exercise
//! the real request construction + response decode without hitting Google.
//! The access token rides in an `Authorization: Bearer` header (never a
//! query string), and `http_client::build_client()` carries the request so
//! a configured Hysteria proxy is honoured.
//!
//! Unlike Todoist (a static API token), Google Tasks needs a short-lived
//! OAuth access token. The operator stores a long-lived **refresh token**
//! (one-time consent via the Google OAuth installed-app flow, scope
//! `https://www.googleapis.com/auth/tasks`); [`refresh_access_token`]
//! exchanges it for a fresh access token on each `neoth todo --provider
//! google` run. The refresh token is the only durable secret; access
//! tokens are never persisted.
//!
//! Credential resolution + the operator CLI surface live in `cli::todo`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

/// Google Tasks REST v1 base. `@default` is the operator's primary task
/// list (every Google account has one). Lifted to a const so the
/// `_against` seams can point tests at a `wiremock::MockServer` URI.
pub const GOOGLE_TASKS_API_BASE: &str = "https://tasks.googleapis.com/tasks/v1";

/// OAuth scope a refresh token must have been granted for the Tasks API.
/// Surfaced so the wizard / docs can show the operator the exact scope to
/// request at consent time.
pub const GOOGLE_TASKS_SCOPE: &str = "https://www.googleapis.com/auth/tasks";

/// One Google task. Only the fields NEOTH surfaces are decoded; Google
/// sends more (`kind`, `etag`, `selfLink`, `position`, …) and serde drops
/// the rest (no `deny_unknown_fields`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct GoogleTask {
    pub id: String,
    #[serde(default)]
    pub title: String,
    /// `"needsAction"` (open) or `"completed"`.
    #[serde(default)]
    pub status: Option<String>,
    /// RFC-3339 timestamp (date-only semantics — Google stores the due
    /// date as midnight UTC). `None` when the task has no due date.
    #[serde(default)]
    pub due: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl GoogleTask {
    /// True when the task is still open (status missing is treated as open
    /// — a freshly created task may omit it).
    pub fn is_open(&self) -> bool {
        self.status.as_deref() != Some("completed")
    }
}

/// The `{ items: [...] }` envelope the list endpoint returns. A list with
/// no tasks omits `items` entirely, so it defaults to empty.
#[derive(Debug, Deserialize)]
struct TaskListResponse {
    #[serde(default)]
    items: Vec<GoogleTask>,
}

/// The token-endpoint JSON response. Only `access_token` is consumed.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Reject task ids that aren't the shape Google uses (base64url-ish:
/// alphanumeric plus `-` and `_`) — the id is interpolated into the
/// `/tasks/{id}` path, so a value containing `/`, `?`, `#`, or whitespace
/// could otherwise re-target the request. Defense-in-depth at the boundary.
fn validate_task_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "google_tasks: invalid task id {id:?} (expected a base64url-shaped Google task id)"
        );
    }
    Ok(())
}

/// Exchange a long-lived refresh token for a short-lived access token via
/// the OAuth `refresh_token` grant. The refresh token + client secret ride
/// in the form body over TLS (the standard OAuth token-exchange shape);
/// they are never logged.
pub async fn refresh_access_token(
    client_id: &str,
    client_secret: &SecretString,
    refresh_token: &SecretString,
) -> Result<SecretString> {
    refresh_access_token_against(
        crate::email::gmail::GOOGLE_OAUTH_TOKEN_ENDPOINT,
        client_id,
        client_secret,
        refresh_token,
    )
    .await
}

async fn refresh_access_token_against(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &SecretString,
    refresh_token: &SecretString,
) -> Result<SecretString> {
    if client_id.is_empty() {
        anyhow::bail!("google_tasks: empty OAuth client_id");
    }
    let client = http_client::build_client()?;
    let resp = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret.expose()),
            ("refresh_token", refresh_token.expose()),
        ])
        .send()
        .await
        .context("google oauth refresh request")?;
    if !resp.status().is_success() {
        // The body can echo the refresh token / client_secret in an error
        // (`invalid_grant` etc.) — surface only the status, never the body.
        anyhow::bail!(
            "google oauth refresh returned {} — the refresh token may be \
             expired/revoked; re-run consent to mint a new one",
            resp.status()
        );
    }
    let token: TokenResponse = resp.json().await.context("google oauth refresh decode")?;
    if token.access_token.is_empty() {
        anyhow::bail!("google oauth refresh returned an empty access_token");
    }
    Ok(SecretString::from(token.access_token))
}

/// List the operator's open tasks on their primary list.
pub async fn list_tasks(access_token: &SecretString) -> Result<Vec<GoogleTask>> {
    list_tasks_against(GOOGLE_TASKS_API_BASE, access_token).await
}

async fn list_tasks_against(base: &str, access_token: &SecretString) -> Result<Vec<GoogleTask>> {
    let client = http_client::build_client()?;
    let resp = client
        .get(format!("{base}/lists/@default/tasks"))
        .query(&[("showCompleted", "false"), ("maxResults", "100")])
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .send()
        .await
        .context("google_tasks list request")?;
    if !resp.status().is_success() {
        anyhow::bail!("google_tasks list returned {}", resp.status());
    }
    let body: TaskListResponse = resp.json().await.context("google_tasks list decode")?;
    Ok(body.items)
}

/// Create a task with the given title; returns the created task (with its
/// server-assigned id).
pub async fn create_task(access_token: &SecretString, title: &str) -> Result<GoogleTask> {
    create_task_against(GOOGLE_TASKS_API_BASE, access_token, title).await
}

async fn create_task_against(
    base: &str,
    access_token: &SecretString,
    title: &str,
) -> Result<GoogleTask> {
    if title.trim().is_empty() {
        anyhow::bail!("google_tasks: empty task title");
    }
    let client = http_client::build_client()?;
    let resp = client
        .post(format!("{base}/lists/@default/tasks"))
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "title": title }))
        .send()
        .await
        .context("google_tasks create request")?;
    if !resp.status().is_success() {
        anyhow::bail!("google_tasks create returned {}", resp.status());
    }
    resp.json().await.context("google_tasks create decode")
}

/// Close (complete) a task by id. Google Tasks has no dedicated close
/// endpoint — completing is a PATCH that sets `status = completed`, which
/// replies `200` with the updated task.
pub async fn close_task(access_token: &SecretString, id: &str) -> Result<()> {
    close_task_against(GOOGLE_TASKS_API_BASE, access_token, id).await
}

async fn close_task_against(base: &str, access_token: &SecretString, id: &str) -> Result<()> {
    validate_task_id(id)?;
    let client = http_client::build_client()?;
    let resp = client
        .patch(format!("{base}/lists/@default/tasks/{id}"))
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "status": "completed" }))
        .send()
        .await
        .context("google_tasks close request")?;
    if !resp.status().is_success() {
        anyhow::bail!("google_tasks close returned {}", resp.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_task_id_accepts_base64url_rejects_path_chars() {
        assert!(validate_task_id("MTIzNDU2Nzg5MDEyMzQ1Njc4").is_ok());
        assert!(validate_task_id("abc-DEF_123").is_ok());
        assert!(validate_task_id("").is_err());
        assert!(validate_task_id("../../etc").is_err());
        assert!(validate_task_id("12/tasks?x=1").is_err());
        assert!(validate_task_id("has space").is_err());
    }

    #[test]
    fn google_task_is_open_treats_missing_status_as_open() {
        let open = GoogleTask {
            id: "1".into(),
            title: "t".into(),
            status: None,
            due: None,
            notes: None,
        };
        assert!(open.is_open());
        let done = GoogleTask {
            status: Some("completed".into()),
            ..open.clone()
        };
        assert!(!done.is_open());
        let needs = GoogleTask {
            status: Some("needsAction".into()),
            ..open
        };
        assert!(needs.is_open());
    }

    #[tokio::test]
    async fn create_task_rejects_empty_title_before_any_request() {
        let err = create_task(&SecretString::from("ya29.x"), "   ")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty task title"));
    }

    #[tokio::test]
    async fn refresh_exchanges_refresh_token_for_access_token() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=rt-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.fresh",
                "expires_in": 3599,
                "token_type": "Bearer"
            })))
            .mount(&mock)
            .await;
        let tok = refresh_access_token_against(
            &format!("{}/token", mock.uri()),
            "client-abc.apps.googleusercontent.com",
            &SecretString::from("secret-xyz"),
            &SecretString::from("rt-123"),
        )
        .await
        .expect("refresh");
        assert_eq!(tok.expose(), "ya29.fresh");
    }

    #[tokio::test]
    async fn refresh_surfaces_invalid_grant_without_leaking_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "refresh_token": "rt-SHOULD-NOT-LEAK"
            })))
            .mount(&mock)
            .await;
        let err = refresh_access_token_against(
            &format!("{}/token", mock.uri()),
            "cid",
            &SecretString::from("s"),
            &SecretString::from("rt-SHOULD-NOT-LEAK"),
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("400"), "status surfaced: {msg}");
        assert!(
            !msg.contains("rt-SHOULD-NOT-LEAK"),
            "error must NOT echo the refresh token: {msg}"
        );
    }

    #[tokio::test]
    async fn list_decodes_items_envelope_and_sends_bearer() {
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lists/@default/tasks"))
            .and(query_param("showCompleted", "false"))
            .and(header("authorization", "Bearer ya29.tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "tasks#tasks",
                "items": [
                    {"id": "abc-1", "title": "buy milk", "status": "needsAction"},
                    {"id": "abc-2", "title": "ship 1.0", "status": "needsAction", "due": "2026-06-01T00:00:00.000Z"}
                ]
            })))
            .mount(&mock)
            .await;
        let tasks = list_tasks_against(&mock.uri(), &SecretString::from("ya29.tok"))
            .await
            .expect("list decode");
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].title, "buy milk");
        assert_eq!(tasks[1].id, "abc-2");
        assert_eq!(tasks[1].due.as_deref(), Some("2026-06-01T00:00:00.000Z"));
    }

    #[tokio::test]
    async fn list_empty_when_items_absent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lists/@default/tasks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "kind": "tasks#tasks" })),
            )
            .mount(&mock)
            .await;
        let tasks = list_tasks_against(&mock.uri(), &SecretString::from("t"))
            .await
            .expect("empty list");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn create_posts_title_and_returns_task() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/lists/@default/tasks"))
            .and(header("authorization", "Bearer t"))
            .and(body_json(serde_json::json!({ "title": "write tests" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"id": "new-99", "title": "write tests", "status": "needsAction"}
            )))
            .mount(&mock)
            .await;
        let task = create_task_against(&mock.uri(), &SecretString::from("t"), "write tests")
            .await
            .expect("create");
        assert_eq!(task.id, "new-99");
        assert_eq!(task.title, "write tests");
    }

    #[tokio::test]
    async fn close_patches_status_completed() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/lists/@default/tasks/new-99"))
            .and(header("authorization", "Bearer t"))
            .and(body_json(serde_json::json!({ "status": "completed" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"id": "new-99", "title": "x", "status": "completed"}
            )))
            .mount(&mock)
            .await;
        close_task_against(&mock.uri(), &SecretString::from("t"), "new-99")
            .await
            .expect("close 200");
    }

    #[tokio::test]
    async fn close_surfaces_non_success_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/lists/@default/tasks/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = close_task_against(&mock.uri(), &SecretString::from("t"), "missing")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
    }
}
