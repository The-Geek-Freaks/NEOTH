//! `todoist` — TD-01. Todoist REST v2 adapter: list / create / close.
//!
//! A small outbound REST client in the same shape as
//! [`super::web_search`] — `http_client::build_client()` carries the
//! request (so a configured Hysteria proxy is honoured), the token rides
//! in an `Authorization: Bearer` header (never in a query string or body
//! where middleware/logs could capture it), and each public fn delegates
//! to an `_against(base, …)` seam so the wiremock tests exercise the real
//! request construction + response decode without hitting api.todoist.com.
//!
//! Token resolution + the operator CLI surface live in `cli::todo`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

/// Todoist REST v2 base. Lifted to a const so the `_against` seams can
/// point the tests at a `wiremock::MockServer` URI instead.
pub const TODOIST_API_BASE: &str = "https://api.todoist.com/rest/v2";

/// One Todoist task. Only the fields NEOTH surfaces are decoded; Todoist
/// sends many more and serde drops the rest (no `deny_unknown_fields`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct TodoistTask {
    pub id: String,
    pub content: String,
    #[serde(default)]
    pub is_completed: bool,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub due: Option<TodoistDue>,
}

/// The due-date sub-object (all fields optional — a task may have no due).
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct TodoistDue {
    #[serde(default)]
    pub string: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
}

/// Reject task ids that aren't the alphanumeric shape Todoist v2 uses —
/// the id is interpolated into the `/tasks/{id}/close` path, so a value
/// containing `/`, `?`, `#`, or whitespace could otherwise re-target the
/// request. Defense-in-depth: ids come from the operator CLI / a prior
/// list, but validating at the boundary keeps the path injection-free.
fn validate_task_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        anyhow::bail!("todoist: invalid task id {id:?} (expected an alphanumeric Todoist v2 id)");
    }
    Ok(())
}

/// List the operator's active (open) tasks.
pub async fn list_tasks(token: &SecretString) -> Result<Vec<TodoistTask>> {
    list_tasks_against(TODOIST_API_BASE, token).await
}

async fn list_tasks_against(base: &str, token: &SecretString) -> Result<Vec<TodoistTask>> {
    let client = http_client::build_client()?;
    let resp = client
        .get(format!("{base}/tasks"))
        .header("Authorization", format!("Bearer {}", token.expose()))
        .send()
        .await
        .context("todoist list request")?;
    if !resp.status().is_success() {
        anyhow::bail!("todoist list returned {}", resp.status());
    }
    resp.json().await.context("todoist list decode")
}

/// Create a task with the given content; returns the created task (with
/// its server-assigned id).
pub async fn create_task(token: &SecretString, content: &str) -> Result<TodoistTask> {
    create_task_against(TODOIST_API_BASE, token, content).await
}

async fn create_task_against(
    base: &str,
    token: &SecretString,
    content: &str,
) -> Result<TodoistTask> {
    if content.trim().is_empty() {
        anyhow::bail!("todoist: empty task content");
    }
    let client = http_client::build_client()?;
    let resp = client
        .post(format!("{base}/tasks"))
        .header("Authorization", format!("Bearer {}", token.expose()))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "content": content }))
        .send()
        .await
        .context("todoist create request")?;
    if !resp.status().is_success() {
        anyhow::bail!("todoist create returned {}", resp.status());
    }
    resp.json().await.context("todoist create decode")
}

/// Close (complete) a task by id. Todoist replies `204 No Content` on
/// success — there is no body to decode.
pub async fn close_task(token: &SecretString, id: &str) -> Result<()> {
    close_task_against(TODOIST_API_BASE, token, id).await
}

async fn close_task_against(base: &str, token: &SecretString, id: &str) -> Result<()> {
    validate_task_id(id)?;
    let client = http_client::build_client()?;
    let resp = client
        .post(format!("{base}/tasks/{id}/close"))
        .header("Authorization", format!("Bearer {}", token.expose()))
        .send()
        .await
        .context("todoist close request")?;
    if !resp.status().is_success() {
        anyhow::bail!("todoist close returned {}", resp.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_task_id_accepts_alphanumeric_rejects_path_chars() {
        assert!(validate_task_id("2995104339").is_ok());
        assert!(validate_task_id("abcDEF123").is_ok());
        assert!(validate_task_id("").is_err());
        assert!(validate_task_id("../../etc").is_err());
        assert!(validate_task_id("12/close?x=1").is_err());
        assert!(validate_task_id("has space").is_err());
    }

    #[tokio::test]
    async fn create_task_rejects_empty_content_before_any_request() {
        let err = create_task(&SecretString::from("tok"), "   ")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty task content"));
    }

    #[tokio::test]
    async fn list_decodes_task_array_and_sends_bearer() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tasks"))
            .and(header("authorization", "Bearer todo-key-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "1", "content": "buy milk", "is_completed": false, "priority": 1},
                {"id": "2", "content": "ship v1.0", "due": {"string": "tomorrow", "date": "2026-05-31"}}
            ])))
            .mount(&mock)
            .await;
        let tasks = list_tasks_against(&mock.uri(), &SecretString::from("todo-key-1"))
            .await
            .expect("list decode");
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].content, "buy milk");
        assert_eq!(tasks[1].id, "2");
        assert_eq!(
            tasks[1].due.as_ref().and_then(|d| d.date.as_deref()),
            Some("2026-05-31")
        );
    }

    #[tokio::test]
    async fn create_posts_content_and_returns_task() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tasks"))
            .and(header("authorization", "Bearer k"))
            .and(body_json(serde_json::json!({ "content": "write tests" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"id": "99", "content": "write tests", "is_completed": false}
            )))
            .mount(&mock)
            .await;
        let task = create_task_against(&mock.uri(), &SecretString::from("k"), "write tests")
            .await
            .expect("create");
        assert_eq!(task.id, "99");
        assert_eq!(task.content, "write tests");
    }

    #[tokio::test]
    async fn close_treats_204_as_success() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tasks/99/close"))
            .and(header("authorization", "Bearer k"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;
        close_task_against(&mock.uri(), &SecretString::from("k"), "99")
            .await
            .expect("close 204");
    }

    #[tokio::test]
    async fn close_surfaces_non_success_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tasks/77/close"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = close_task_against(&mock.uri(), &SecretString::from("k"), "77")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
    }
}
