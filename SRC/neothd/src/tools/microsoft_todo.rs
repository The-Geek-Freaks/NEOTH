//! `microsoft_todo` — TD-02. Microsoft To Do adapter (MS Graph) with
//! OAuth-refresh: list / create / close over `graph.microsoft.com/v1.0/me/todo`.
//!
//! Same shape as the sibling [`super::google_tasks`] adapter: every public fn
//! delegates to an `_against(base, …)` seam so the wiremock tests exercise the
//! real request construction + response decode without hitting Microsoft. The
//! access token rides in an `Authorization: Bearer` header (never a query
//! string), and `http_client::build_client()` carries the request.
//!
//! Unlike Google Tasks (a single primary list reachable at `@default`), MS
//! Graph To Do has no default-list alias — the default list is the one whose
//! `wellknownListName == "defaultList"`. So each operation first resolves the
//! default list id ([`default_list_id_against`]) then operates on
//! `/me/todo/lists/{id}/tasks`.
//!
//! The operator stores a long-lived **refresh token** (one-time consent, scope
//! `Tasks.ReadWrite offline_access`); [`refresh_access_token`] exchanges it for
//! a fresh access token per run. Only the refresh token + client secret are
//! durable; access tokens are never persisted. Credential resolution + the CLI
//! surface live in `cli::todo`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

/// MS Graph base for the operator's To Do collection.
pub const MS_GRAPH_TODO_BASE: &str = "https://graph.microsoft.com/v1.0/me/todo";

/// OAuth scope a refresh token must carry (delegated Tasks read/write +
/// offline_access for the refresh token itself).
pub const MS_TODO_SCOPE: &str = "Tasks.ReadWrite offline_access";

/// Build the tenant-scoped token endpoint. `common` works for both work/school
/// and personal Microsoft accounts; an operator with a single-tenant app passes
/// their tenant GUID.
pub fn token_endpoint(tenant_id: &str) -> String {
    let tenant = if tenant_id.trim().is_empty() {
        "common"
    } else {
        tenant_id
    };
    format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
}

/// One MS To Do task. Only the fields NEOTH surfaces are decoded; Graph sends
/// more and serde drops the rest.
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct MicrosoftTask {
    pub id: String,
    #[serde(default)]
    pub title: String,
    /// `"notStarted"` / `"inProgress"` (open) or `"completed"`.
    #[serde(default)]
    pub status: Option<String>,
    /// Due date when set (Graph nests it under `dueDateTime.dateTime`).
    #[serde(rename = "dueDateTime", default)]
    pub due: Option<DueDateTime>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct DueDateTime {
    #[serde(rename = "dateTime", default)]
    pub date_time: String,
}

impl MicrosoftTask {
    /// True when the task is still open (missing status treated as open).
    pub fn is_open(&self) -> bool {
        self.status.as_deref() != Some("completed")
    }
}

/// `{ value: [...] }` envelope Graph returns for collections.
#[derive(Debug, Deserialize)]
struct GraphCollection<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct TodoList {
    id: String,
    #[serde(rename = "wellknownListName", default)]
    wellknown_list_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Reject task / list ids that aren't Graph-shaped (it interpolates them into
/// the request path). Graph ids are base64url-ish plus `=`; reject anything that
/// could re-target the request (`/`, `?`, `#`, whitespace).
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=' | '.'))
    {
        anyhow::bail!("microsoft_todo: invalid id {id:?} (unexpected characters)");
    }
    Ok(())
}

/// Exchange a refresh token for an access token via the OAuth `refresh_token`
/// grant. Secrets ride in the TLS form body; the error path surfaces only the
/// HTTP status (the body can echo the secret on `invalid_grant`).
pub async fn refresh_access_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &SecretString,
    refresh_token: &SecretString,
) -> Result<SecretString> {
    refresh_access_token_against(
        &token_endpoint(tenant_id),
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
        anyhow::bail!("microsoft_todo: empty OAuth client_id");
    }
    let resp = http_client::build_client()?
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret.expose()),
            ("refresh_token", refresh_token.expose()),
            ("scope", MS_TODO_SCOPE),
        ])
        .send()
        .await
        .context("microsoft oauth refresh request")?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "microsoft oauth refresh returned {} — the refresh token may be \
             expired/revoked; re-run consent to mint a new one",
            resp.status()
        );
    }
    let token: TokenResponse = resp
        .json()
        .await
        .context("microsoft oauth refresh decode")?;
    if token.access_token.is_empty() {
        anyhow::bail!("microsoft oauth refresh returned an empty access_token");
    }
    Ok(SecretString::from(token.access_token))
}

/// Resolve the id of the operator's default To Do list (`wellknownListName ==
/// defaultList`), falling back to the first list when Graph doesn't tag one.
async fn default_list_id_against(base: &str, access_token: &SecretString) -> Result<String> {
    let resp = http_client::build_client()?
        .get(format!("{base}/lists"))
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .send()
        .await
        .context("microsoft_todo lists request")?;
    if !resp.status().is_success() {
        anyhow::bail!("microsoft_todo lists returned {}", resp.status());
    }
    let body: GraphCollection<TodoList> =
        resp.json().await.context("microsoft_todo lists decode")?;
    body.value
        .iter()
        .find(|l| l.wellknown_list_name.as_deref() == Some("defaultList"))
        .or_else(|| body.value.first())
        .map(|l| l.id.clone())
        .ok_or_else(|| anyhow::anyhow!("microsoft_todo: no To Do lists on this account"))
}

/// List the operator's open tasks on their default list.
pub async fn list_tasks(access_token: &SecretString) -> Result<Vec<MicrosoftTask>> {
    list_tasks_against(MS_GRAPH_TODO_BASE, access_token).await
}

async fn list_tasks_against(base: &str, access_token: &SecretString) -> Result<Vec<MicrosoftTask>> {
    let list_id = default_list_id_against(base, access_token).await?;
    validate_id(&list_id)?;
    let resp = http_client::build_client()?
        .get(format!("{base}/lists/{list_id}/tasks"))
        .query(&[("$filter", "status ne 'completed'")])
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .send()
        .await
        .context("microsoft_todo list request")?;
    if !resp.status().is_success() {
        anyhow::bail!("microsoft_todo list returned {}", resp.status());
    }
    let body: GraphCollection<MicrosoftTask> =
        resp.json().await.context("microsoft_todo list decode")?;
    Ok(body.value)
}

/// Create a task with the given title; returns the created task.
pub async fn create_task(access_token: &SecretString, title: &str) -> Result<MicrosoftTask> {
    create_task_against(MS_GRAPH_TODO_BASE, access_token, title).await
}

async fn create_task_against(
    base: &str,
    access_token: &SecretString,
    title: &str,
) -> Result<MicrosoftTask> {
    if title.trim().is_empty() {
        anyhow::bail!("microsoft_todo: empty task title");
    }
    let list_id = default_list_id_against(base, access_token).await?;
    validate_id(&list_id)?;
    let resp = http_client::build_client()?
        .post(format!("{base}/lists/{list_id}/tasks"))
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "title": title }))
        .send()
        .await
        .context("microsoft_todo create request")?;
    if !resp.status().is_success() {
        anyhow::bail!("microsoft_todo create returned {}", resp.status());
    }
    resp.json().await.context("microsoft_todo create decode")
}

/// Close (complete) a task by id — PATCH `status = completed`.
pub async fn close_task(access_token: &SecretString, id: &str) -> Result<()> {
    close_task_against(MS_GRAPH_TODO_BASE, access_token, id).await
}

async fn close_task_against(base: &str, access_token: &SecretString, id: &str) -> Result<()> {
    validate_id(id)?;
    let list_id = default_list_id_against(base, access_token).await?;
    validate_id(&list_id)?;
    let resp = http_client::build_client()?
        .patch(format!("{base}/lists/{list_id}/tasks/{id}"))
        .header("Authorization", format!("Bearer {}", access_token.expose()))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "status": "completed" }))
        .send()
        .await
        .context("microsoft_todo close request")?;
    if !resp.status().is_success() {
        anyhow::bail!("microsoft_todo close returned {}", resp.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_endpoint_defaults_to_common() {
        assert!(token_endpoint("").ends_with("/common/oauth2/v2.0/token"));
        assert!(token_endpoint("tenant-guid").contains("/tenant-guid/"));
    }

    #[test]
    fn validate_id_rejects_path_chars() {
        assert!(validate_id("AAMkAD-abc_123=").is_ok());
        assert!(validate_id("").is_err());
        assert!(validate_id("../../etc").is_err());
        assert!(validate_id("a/b?c").is_err());
        assert!(validate_id("has space").is_err());
    }

    #[test]
    fn is_open_treats_missing_status_as_open() {
        let t = MicrosoftTask {
            id: "1".into(),
            title: "t".into(),
            status: None,
            due: None,
        };
        assert!(t.is_open());
        assert!(
            !MicrosoftTask {
                status: Some("completed".into()),
                ..t.clone()
            }
            .is_open()
        );
    }

    #[tokio::test]
    async fn create_rejects_empty_title_before_any_request() {
        let err = create_task(&SecretString::from("tok"), "  ")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty task title"));
    }

    #[tokio::test]
    async fn refresh_exchanges_token_and_sends_scope() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("scope=Tasks.ReadWrite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "eyJ.fresh", "token_type": "Bearer", "expires_in": 3599
            })))
            .mount(&mock)
            .await;
        let tok = refresh_access_token_against(
            &format!("{}/token", mock.uri()),
            "client-abc",
            &SecretString::from("sec"),
            &SecretString::from("rt-1"),
        )
        .await
        .expect("refresh");
        assert_eq!(tok.expose(), "eyJ.fresh");
    }

    #[tokio::test]
    async fn refresh_surfaces_status_without_leaking_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant", "refresh_token": "rt-LEAK"
            })))
            .mount(&mock)
            .await;
        let err = refresh_access_token_against(
            &format!("{}/token", mock.uri()),
            "cid",
            &SecretString::from("s"),
            &SecretString::from("rt-LEAK"),
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("400"));
        assert!(
            !msg.contains("rt-LEAK"),
            "must not echo refresh token: {msg}"
        );
    }

    /// Mount the default-list lookup so the task ops can resolve it.
    async fn mount_default_list(mock: &wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "other-list", "wellknownListName": "none"},
                    {"id": "default-list-id", "wellknownListName": "defaultList"}
                ]
            })))
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn list_resolves_default_then_decodes_value_envelope() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        mount_default_list(&mock).await;
        Mock::given(method("GET"))
            .and(path("/lists/default-list-id/tasks"))
            .and(header("authorization", "Bearer t"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "task-1", "title": "buy milk", "status": "notStarted"},
                    {"id": "task-2", "title": "ship 1.0", "status": "notStarted",
                     "dueDateTime": {"dateTime": "2026-06-01T00:00:00", "timeZone": "UTC"}}
                ]
            })))
            .mount(&mock)
            .await;
        let tasks = list_tasks_against(&mock.uri(), &SecretString::from("t"))
            .await
            .expect("list");
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].title, "buy milk");
        assert_eq!(
            tasks[1].due.as_ref().map(|d| d.date_time.as_str()),
            Some("2026-06-01T00:00:00")
        );
    }

    #[tokio::test]
    async fn create_posts_title_to_default_list() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        mount_default_list(&mock).await;
        Mock::given(method("POST"))
            .and(path("/lists/default-list-id/tasks"))
            .and(body_json(serde_json::json!({ "title": "write tests" })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!(
                {"id": "new-1", "title": "write tests", "status": "notStarted"}
            )))
            .mount(&mock)
            .await;
        let task = create_task_against(&mock.uri(), &SecretString::from("t"), "write tests")
            .await
            .expect("create");
        assert_eq!(task.id, "new-1");
        assert!(task.is_open());
    }

    #[tokio::test]
    async fn close_patches_status_completed() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        mount_default_list(&mock).await;
        Mock::given(method("PATCH"))
            .and(path("/lists/default-list-id/tasks/task-9"))
            .and(body_json(serde_json::json!({ "status": "completed" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"id": "task-9", "title": "x", "status": "completed"}
            )))
            .mount(&mock)
            .await;
        close_task_against(&mock.uri(), &SecretString::from("t"), "task-9")
            .await
            .expect("close 200");
    }

    #[tokio::test]
    async fn close_surfaces_non_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        mount_default_list(&mock).await;
        Mock::given(method("PATCH"))
            .and(path("/lists/default-list-id/tasks/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = close_task_against(&mock.uri(), &SecretString::from("t"), "missing")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"));
    }
}
