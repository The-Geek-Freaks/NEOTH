//! Authenticated diagnostics for an already configured local Paperless API.
//! API contract inspected at paperless-ngx c63afb47b27951cb6c61e68b6d77a5fd0eedd686.
//! A reported version is not evidence of an OCI digest or managed installation.

use std::{path::Path, time::Duration};

use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode, header};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{LoopbackHttpEndpoint, credentials::Credentials};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 32 * 1024;

/// Only public observations; never includes a URL, user profile or credential.
#[derive(Debug, Serialize)]
pub struct PaperlessReadiness {
    pub status: &'static str,
    pub authenticated_api_ready: bool,
    pub version: Option<String>,
    pub artifact_verified: bool,
    /// Native prepared-directory observation, separate from API and OCI proof.
    pub staging: &'static str,
}

impl PaperlessReadiness {
    fn unavailable(status: &'static str) -> Self {
        Self {
            status,
            authenticated_api_ready: false,
            version: None,
            artifact_verified: false,
            staging: "not_checked",
        }
    }
}

/// Uses stored credentials only; one deadline bounds the complete observation.
pub async fn probe_configured_paperless(credentials: &Credentials) -> PaperlessReadiness {
    probe_with_timeout(credentials, PROBE_TIMEOUT).await
}

/// Probe API readiness and the fixed instance-owned preparation separately.
pub async fn probe_configured_paperless_at(
    home: &Path,
    credentials: &Credentials,
) -> PaperlessReadiness {
    let mut readiness = probe_with_timeout(credentials, PROBE_TIMEOUT).await;
    readiness.staging = match crate::installers::paperless_staging::inspect_at(
        &crate::config::InstancePaths::for_home(home).paperless_root,
    )
    .status
    {
        crate::installers::paperless_staging::PaperlessStagingStatus::NotPrepared => "not_prepared",
        crate::installers::paperless_staging::PaperlessStagingStatus::PreparedPinned => {
            "prepared_pinned"
        }
        crate::installers::paperless_staging::PaperlessStagingStatus::AlreadyPrepared => {
            "already_prepared"
        }
        crate::installers::paperless_staging::PaperlessStagingStatus::UnownedOrMismatch => {
            "unowned_or_mismatch"
        }
    };
    readiness.artifact_verified = false;
    readiness
}

async fn probe_with_timeout(credentials: &Credentials, timeout: Duration) -> PaperlessReadiness {
    let Some(url) = credentials.paperless_url.as_deref() else {
        return PaperlessReadiness::unavailable("not_configured");
    };
    let Ok(endpoint) = LoopbackHttpEndpoint::parse(url) else {
        return PaperlessReadiness::unavailable("unsupported_endpoint");
    };
    let Some(token) = credentials.paperless_token.as_ref() else {
        return PaperlessReadiness::unavailable("credentials_missing");
    };
    if token.expose_secret().is_empty() || token.expose_secret().len() > 4096 {
        return PaperlessReadiness::unavailable("invalid_credentials");
    }
    let raw_header = Zeroizing::new(format!("Token {}", token.expose_secret()));
    let Ok(mut authorization) = header::HeaderValue::from_str(&raw_header) else {
        return PaperlessReadiness::unavailable("invalid_credentials");
    };
    authorization.set_sensitive(true);
    let Ok(client) = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
    else {
        return PaperlessReadiness::unavailable("transport_error");
    };
    match tokio::time::timeout(timeout, probe(&client, &endpoint, authorization)).await {
        Ok(Ok(readiness)) => readiness,
        Ok(Err(code)) => PaperlessReadiness::unavailable(code),
        Err(_) => PaperlessReadiness::unavailable("timeout"),
    }
}

async fn probe(
    client: &Client,
    endpoint: &LoopbackHttpEndpoint,
    authorization: header::HeaderValue,
) -> Result<PaperlessReadiness, &'static str> {
    let profile_url = format!("{}/api/profile/", endpoint.origin());
    let control = client
        .get(&profile_url)
        .send()
        .await
        .map_err(transport_error)?;
    if control.status().is_redirection() {
        return Err("redirect_rejected");
    }
    if !matches!(
        control.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err("authentication_not_enforced");
    }
    drop(control);

    let profile = client
        .get(profile_url)
        .header(header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(transport_error)?;
    require_success(&profile)?;
    let body = bounded_json_body(profile).await?;
    // ProfileSerializer also returns auth_token and personal fields. Ignore
    // them during deserialization and zero the bounded raw buffer on drop.
    let _: ProfileShape = serde_json::from_slice(&body).map_err(|_| "invalid_response")?;
    drop(body);

    let status = client
        .get(format!("{}/api/status/", endpoint.origin()))
        .header(header::AUTHORIZATION, authorization)
        .send()
        .await
        .map_err(transport_error)?;
    if status.status() == StatusCode::FORBIDDEN {
        return Ok(PaperlessReadiness {
            status: "authenticated_status_permission_required",
            authenticated_api_ready: true,
            version: None,
            artifact_verified: false,
            staging: "not_checked",
        });
    }
    require_success(&status)?;
    let body = bounded_json_body(status).await?;
    let status: SystemStatus = serde_json::from_slice(&body).map_err(|_| "invalid_response")?;
    let version = status.pngx_version;
    // Return stable release numbers only, never arbitrary server text or build
    // metadata that could contain profile data or a reflected credential.
    let parts: Vec<_> = version.split('.').collect();
    if version.len() > 24
        || parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 6 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("unsupported_version");
    }
    Ok(PaperlessReadiness {
        status: "authenticated_api_ready",
        authenticated_api_ready: true,
        version: Some(version),
        artifact_verified: false,
        staging: "not_checked",
    })
}

#[derive(Deserialize)]
struct ProfileShape {
    #[serde(rename = "has_usable_password")]
    _has_usable_password: bool,
    #[serde(rename = "is_mfa_enabled")]
    _is_mfa_enabled: bool,
    #[serde(rename = "social_accounts")]
    _social_accounts: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct SystemStatus {
    pngx_version: String,
}

fn transport_error(error: reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else {
        "transport_error"
    }
}

fn require_success(response: &Response) -> Result<(), &'static str> {
    if response.status().is_redirection() {
        Err("redirect_rejected")
    } else if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        Err("unauthorized")
    } else if response.status() != StatusCode::OK {
        Err("invalid_response")
    } else {
        Ok(())
    }
}

async fn bounded_json_body(response: Response) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let json_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json_type {
        return Err("invalid_response");
    }
    if response
        .content_length()
        .is_some_and(|size| size > BODY_LIMIT as u64)
    {
        return Err("response_too_large");
    }
    let mut body = Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(transport_error)?;
        if body.len().saturating_add(chunk.len()) > BODY_LIMIT {
            return Err("response_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
#[path = "paperless_readiness_tests.rs"]
mod tests;
