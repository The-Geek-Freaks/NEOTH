//! Read-only live readiness probes shared by the channel CLI and daemon
//! reconciler. Probes never send a chat message, never follow redirects, cap
//! response bodies, and use short per-request timeouts.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use crate::secret::SecretString;

pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_PROBE_BODY: usize = 64 * 1024;

/// Parse an operator base URL without allowing embedded credentials, query
/// secrets, or fragments. Callers append only fixed protocol paths.
pub(crate) fn parse_base_url(raw: &str, channel: &str) -> Result<Url> {
    let url = Url::parse(raw.trim()).with_context(|| format!("{channel}: invalid base URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("{channel}: base URL must be absolute http(s)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{channel}: base URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("{channel}: base URL must not contain a query or fragment");
    }
    Ok(url)
}

/// Append a fixed API path while preserving reverse-proxy path prefixes.
pub(crate) fn append_path(mut base: Url, suffix: &str) -> Url {
    let mut path = base.path().trim_end_matches('/').to_string();
    path.push('/');
    path.push_str(suffix.trim_start_matches('/'));
    base.set_path(&path);
    base
}

/// Loopback probes bypass proxy state; remote probes still honour the daemon's
/// configured egress proxy. Both variants reject redirects.
pub(crate) fn probe_client(url: &Url) -> Result<reqwest::Client> {
    let loopback = match url.host_str().unwrap_or_default() {
        "localhost" => true,
        host => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
    };
    if loopback {
        crate::providers::http_client::build_direct_client_no_redirect()
    } else {
        crate::providers::http_client::build_client_no_redirect()
    }
}

/// Consume a response body under a hard allocation cap. Error text is static:
/// a transport implementation must never smuggle an Authorization header or a
/// query-carried BlueBubbles password into operator-visible output.
pub(crate) async fn bounded_body(
    mut response: reqwest::Response,
    context: &'static str,
) -> Result<(StatusCode, Vec<u8>)> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROBE_BODY as u64)
    {
        anyhow::bail!("{context} response exceeds {MAX_PROBE_BODY} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("{context} response body read failed"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_PROBE_BODY {
            anyhow::bail!("{context} response exceeds {MAX_PROBE_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

#[derive(Debug, Deserialize)]
struct TwitchValidation {
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

pub(crate) async fn probe_twitch(username: &str, token: &SecretString) -> Result<String> {
    probe_twitch_at(
        Url::parse("https://id.twitch.tv/oauth2/validate").expect("static URL"),
        username,
        token,
    )
    .await
}

async fn probe_twitch_at(endpoint: Url, username: &str, token: &SecretString) -> Result<String> {
    let client = probe_client(&endpoint)?;
    let raw_token = token
        .expose()
        .strip_prefix("oauth:")
        .unwrap_or(token.expose());
    let response = client
        .get(endpoint)
        .header(reqwest::header::AUTHORIZATION, format!("OAuth {raw_token}"))
        .timeout(PROBE_TIMEOUT)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Twitch token validation request failed"))?;
    let (status, body) = bounded_body(response, "Twitch token validation").await?;
    if status == StatusCode::UNAUTHORIZED {
        anyhow::bail!("Twitch rejected the OAuth token");
    }
    if !status.is_success() {
        anyhow::bail!("Twitch token validation returned HTTP {}", status.as_u16());
    }
    let validation: TwitchValidation =
        serde_json::from_slice(&body).context("Twitch token validation returned malformed JSON")?;
    let login = validation
        .login
        .filter(|login| !login.trim().is_empty())
        .context("Twitch token is not a user token")?;
    if !login.eq_ignore_ascii_case(username.trim()) {
        anyhow::bail!(
            "Twitch token belongs to `{login}`, but twitch_username is `{}`",
            username.trim()
        );
    }
    for required in ["chat:read", "chat:edit"] {
        if !validation.scopes.iter().any(|scope| scope == required) {
            anyhow::bail!("Twitch token is missing required `{required}` scope");
        }
    }
    Ok(format!(
        "OAuth token valid for {login} ({}) with chat:read + chat:edit",
        validation.user_id.as_deref().unwrap_or("unknown user id")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn base_url_rejects_credentials_query_and_fragment() {
        for raw in [
            "https://user:pw@example.com",
            "https://example.com?token=x",
            "https://example.com/#fragment",
            "ftp://example.com",
        ] {
            assert!(parse_base_url(raw, "test").is_err(), "accepted {raw}");
        }
    }

    #[tokio::test]
    async fn bounded_body_rejects_oversized_stream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_PROBE_BODY + 1]))
            .mount(&server)
            .await;
        let response = reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .unwrap();
        assert!(bounded_body(response, "test").await.is_err());
    }

    #[tokio::test]
    async fn twitch_probe_validates_identity_scopes_and_hides_token() {
        let server = MockServer::start().await;
        let secret = SecretString::from("super-secret-token");
        Mock::given(method("GET"))
            .and(path("/oauth2/validate"))
            .and(header("authorization", "OAuth super-secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "login": "alex",
                "user_id": "u1",
                "scopes": ["chat:read", "chat:edit"]
            })))
            .mount(&server)
            .await;
        let endpoint = Url::parse(&format!("{}/oauth2/validate", server.uri())).unwrap();
        let result = probe_twitch_at(endpoint, "Alex", &secret).await.unwrap();
        assert!(result.contains("alex"));

        let bad_endpoint = Url::parse("http://127.0.0.1:1/oauth2/validate").unwrap();
        let error = probe_twitch_at(bad_endpoint, "alex", &secret)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret.expose()));
    }
}
