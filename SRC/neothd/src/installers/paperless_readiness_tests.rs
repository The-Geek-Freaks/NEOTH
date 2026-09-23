use super::*;

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const TOKEN: &str = "paperless-test-token";
const PROFILE: &str = r#"{"has_usable_password":true,"is_mfa_enabled":false,"social_accounts":[]}"#;
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(1);

fn response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn credentials(port: u16) -> crate::config::Credentials {
    crate::config::Credentials {
        paperless_url: Some(format!("http://127.0.0.1:{port}")),
        paperless_token: Some(crate::secret::SecretString::new(TOKEN.to_owned())),
        ..Default::default()
    }
}

struct ReapedTask<T> {
    task: JoinHandle<T>,
}

impl<T> ReapedTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task }
    }

    async fn finish(mut self) -> T {
        match tokio::time::timeout(FIXTURE_TIMEOUT, &mut self.task).await {
            Ok(result) => result.expect("bounded loopback fixture task must complete"),
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                panic!("bounded loopback fixture task did not complete")
            }
        }
    }
}

impl<T> Drop for ReapedTask<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ScriptedLoopback {
    credentials: crate::config::Credentials,
    task: ReapedTask<Vec<String>>,
}

async fn read_headers(stream: &mut TcpStream) -> String {
    let mut headers = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 512];
        let count = tokio::time::timeout(FIXTURE_TIMEOUT, stream.read(&mut chunk))
            .await
            .expect("bounded loopback request read")
            .expect("read loopback request");
        assert!(count > 0, "loopback client closed before complete headers");
        headers.extend_from_slice(&chunk[..count]);
        assert!(headers.len() <= 8 * 1024, "loopback request headers exceeded cap");
        if headers.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8_lossy(&headers).into_owned();
        }
    }
}

async fn scripted_loopback(responses: Vec<String>) -> ScriptedLoopback {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let credentials = credentials(listener.local_addr().unwrap().port());
    let task = tokio::spawn(async move {
        let mut requests = Vec::with_capacity(responses.len());
        for response in responses {
            let (mut stream, _) = tokio::time::timeout(FIXTURE_TIMEOUT, listener.accept())
                .await
                .expect("bounded loopback accept")
                .expect("accept loopback client");
            requests.push(read_headers(&mut stream).await);
            tokio::time::timeout(FIXTURE_TIMEOUT, stream.write_all(response.as_bytes()))
                .await
                .expect("bounded loopback response write")
                .expect("write loopback response");
        }
        requests
    });
    ScriptedLoopback {
        credentials,
        task: ReapedTask::new(task),
    }
}

fn assert_auth_sequence(requests: &[String]) {
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/profile/ "));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
    assert!(requests[1].starts_with("GET /api/profile/ "));
    assert!(requests[2].starts_with("GET /api/status/ "));
    for request in &requests[1..] {
        assert!(has_test_authorization(request));
    }
}

fn has_test_authorization(request: &str) -> bool {
    request.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("authorization") && value.trim() == "Token paperless-test-token"
    })
}

#[tokio::test]
async fn configured_probe_requires_unauthenticated_rejection_then_returns_stable_version() {
    let fixture = scripted_loopback(vec![
        response("401 Unauthorized", "text/plain", ""),
        response(
            "200 OK",
            "application/json",
            r#"{"auth_token":"never-expose-paperless-token","email":"operator@example.invalid","has_usable_password":true,"is_mfa_enabled":false,"social_accounts":[]}"#,
        ),
        response("200 OK", "application/json", r#"{"pngx_version":"2.14.3"}"#),
    ])
    .await;

    let readiness = probe_configured_paperless(&fixture.credentials).await;
    assert_eq!(readiness.status, "authenticated_api_ready");
    assert!(readiness.authenticated_api_ready);
    assert_eq!(readiness.version.as_deref(), Some("2.14.3"));
    assert!(!readiness.artifact_verified);
    let public_readiness = serde_json::to_string(&readiness).unwrap();
    assert!(!public_readiness.contains("never-expose-paperless-token"));
    assert!(!public_readiness.contains("operator@example.invalid"));
    assert_auth_sequence(&fixture.task.finish().await);
}

#[tokio::test]
async fn unauthenticated_generic_200_is_not_readiness_evidence() {
    let fixture = scripted_loopback(vec![response(
        "200 OK",
        "application/json",
        PROFILE,
    )])
    .await;

    assert_eq!(
        probe_with_timeout(&fixture.credentials, Duration::from_millis(200))
            .await
            .status,
        "authentication_not_enforced"
    );
    let requests = fixture.task.finish().await;
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
}

#[tokio::test]
async fn authenticated_profile_401_and_403_are_unauthorized() {
    for status in ["401 Unauthorized", "403 Forbidden"] {
        let fixture = scripted_loopback(vec![
            response("401 Unauthorized", "text/plain", ""),
            response(status, "text/plain", ""),
        ])
        .await;

        assert_eq!(
            probe_with_timeout(&fixture.credentials, Duration::from_millis(200))
                .await
                .status,
            "unauthorized"
        );
        let requests = fixture.task.finish().await;
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
        assert!(has_test_authorization(&requests[1]));
    }
}

#[tokio::test]
async fn redirect_is_not_followed_and_does_not_send_token_to_the_redirect_target() {
    let fixture = scripted_loopback(vec![
        response("401 Unauthorized", "text/plain", ""),
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/not-paperless\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    ])
    .await;

    assert_eq!(
        probe_with_timeout(&fixture.credentials, Duration::from_millis(200))
            .await
            .status,
        "redirect_rejected"
    );
    let requests = fixture.task.finish().await;
    assert_eq!(requests.len(), 2, "redirect policy must make no third request");
    assert!(has_test_authorization(&requests[1]));
}

#[tokio::test]
async fn malformed_profile_and_non_json_profile_are_invalid_response() {
    for profile in [
        response("200 OK", "application/json", r#"{"has_usable_password":true}"#),
        response("200 OK", "text/plain", PROFILE),
    ] {
        let fixture = scripted_loopback(vec![
            response("401 Unauthorized", "text/plain", ""),
            profile,
        ])
        .await;
        assert_eq!(
            probe_with_timeout(&fixture.credentials, Duration::from_millis(200))
                .await
                .status,
            "invalid_response"
        );
        assert_eq!(fixture.task.finish().await.len(), 2);
    }
}

#[tokio::test]
async fn authenticated_status_forbidden_reports_ready_without_version() {
    let fixture = scripted_loopback(vec![
        response("401 Unauthorized", "text/plain", ""),
        response("200 OK", "application/json", PROFILE),
        response("403 Forbidden", "text/plain", ""),
    ])
    .await;

    let readiness = probe_with_timeout(&fixture.credentials, Duration::from_millis(200)).await;
    assert_eq!(readiness.status, "authenticated_status_permission_required");
    assert!(readiness.authenticated_api_ready);
    assert_eq!(readiness.version, None);
    assert_auth_sequence(&fixture.task.finish().await);
}

#[tokio::test]
async fn chunked_profile_over_body_cap_is_rejected() {
    let oversized = "x".repeat(32 * 1024 + 1);
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{oversized}\r\n0\r\n\r\n",
        oversized.len()
    );
    let fixture = scripted_loopback(vec![
        response("401 Unauthorized", "text/plain", ""),
        chunked,
    ])
    .await;

    assert_eq!(
        probe_with_timeout(&fixture.credentials, Duration::from_millis(200))
            .await
            .status,
        "response_too_large"
    );
    assert_eq!(fixture.task.finish().await.len(), 2);
}

#[tokio::test]
async fn absolute_timeout_bounds_an_authenticated_profile_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let credentials = credentials(listener.local_addr().unwrap().port());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let server = ReapedTask::new(tokio::spawn(async move {
        let (mut control, _) = tokio::time::timeout(FIXTURE_TIMEOUT, listener.accept())
            .await
            .expect("bounded timeout-fixture control accept")
            .expect("accept timeout-fixture control request");
        let _ = read_headers(&mut control).await;
        tokio::time::timeout(
            FIXTURE_TIMEOUT,
            control.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await
            .expect("bounded timeout-fixture control write")
            .expect("write timeout-fixture control response");
        let (mut authenticated, _) = tokio::time::timeout(FIXTURE_TIMEOUT, listener.accept())
            .await
            .expect("bounded timeout-fixture authenticated accept")
            .expect("accept timeout-fixture authenticated request");
        let _ = read_headers(&mut authenticated).await;
        let _ = entered_tx.send(());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }));

    let probe = ReapedTask::new(tokio::spawn(async move {
        probe_with_timeout(&credentials, Duration::from_millis(200)).await
    }));
    tokio::time::timeout(Duration::from_secs(1), entered_rx)
        .await
        .expect("authenticated request must reach the bounded fixture")
        .expect("fixture must report its authenticated request");
    assert_eq!(probe.finish().await.status, "timeout");
    drop(server);
}
