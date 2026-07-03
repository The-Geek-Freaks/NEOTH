//! AWS Bedrock foundation-models source.
//!
//! Endpoint: `GET https://bedrock.<region>.amazonaws.com/foundation-models`.
//! Note the host is `bedrock.<region>` (control plane), NOT
//! `bedrock-runtime.<region>` (the data-plane host used by the chat
//! adapter). Both sign under `service=bedrock` in the SigV4 scope.
//!
//! Reuses [`crate::providers::aws_sigv4::sign`] + the closed-enum
//! credential chain from [`crate::providers::aws_credentials`].
//! No new AWS dep surface.
//!
//! Reference:
//! <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html>

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::models::catalog::{ModelEntry, SourceOrigin};
use crate::models::sources::{FetchResult, ModelSource};
use crate::providers::aws_credentials::AwsCredentials;
use crate::providers::aws_sigv4::sign;

const PROVIDER_KEY: &str = "aws_bedrock";
const SERVICE_NAME: &str = "bedrock";
const PATH: &str = "/foundation-models";

pub struct BedrockSource {
    region: String,
    credentials: AwsCredentials,
}

impl BedrockSource {
    pub fn new(region: impl Into<String>, credentials: AwsCredentials) -> Self {
        Self {
            region: region.into(),
            credentials,
        }
    }

    fn host(&self) -> String {
        format!("bedrock.{}.amazonaws.com", self.region)
    }

    fn url(&self) -> String {
        format!("https://{}{}", self.host(), PATH)
    }
}

#[async_trait]
impl ModelSource for BedrockSource {
    fn provider(&self) -> &'static str {
        PROVIDER_KEY
    }

    async fn fetch(&self) -> Result<FetchResult> {
        let host = self.host();
        let url = self.url();

        let signed = sign(
            "GET",
            &host,
            PATH,
            "",
            b"",
            &self.region,
            SERVICE_NAME,
            &self.credentials,
            crate::time::utc_now(),
        );

        let client = crate::providers::http_client::build_client()?;
        let mut req = client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .header("host", &host)
            .header("authorization", signed.authorization)
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256);
        if let Some(token) = signed.x_amz_security_token {
            req = req.header("x-amz-security-token", token);
        }
        let response = req.send().await.with_context(|| format!("GET {url}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "aws_bedrock list-foundation-models returned HTTP {}: {}",
                status.as_u16(),
                body.trim()
            );
        }
        let parsed: ListResponse = response
            .json()
            .await
            .context("parse aws_bedrock list-foundation-models JSON")?;
        Ok(FetchResult {
            provider: PROVIDER_KEY,
            origin: SourceOrigin::Api,
            models: parsed
                .model_summaries
                .into_iter()
                .map(|m| {
                    let mut e = ModelEntry::new(m.model_id);
                    if let Some(name) = m.model_name {
                        e = e.with_display_name(name);
                    }
                    if let Some(provider) = m.provider_name {
                        e = e.with_summary(format!("provider={provider}"));
                    }
                    if matches!(
                        m.model_lifecycle.as_ref().map(|l| l.status.as_str()),
                        Some("LEGACY") | Some("EOL")
                    ) {
                        e = e.marked_deprecated();
                    }
                    e
                })
                .collect(),
        })
    }
}

// ── Wire types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse {
    #[serde(default)]
    model_summaries: Vec<ModelSummary>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelSummary {
    model_id: String,
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    provider_name: Option<String>,
    #[serde(default)]
    model_lifecycle: Option<ModelLifecycle>,
}

#[derive(Deserialize)]
struct ModelLifecycle {
    #[serde(default)]
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn dummy_creds() -> AwsCredentials {
        AwsCredentials {
            access_key_id: SecretString::new("AKIATEST".into()),
            secret_access_key: SecretString::new("dummy".into()),
            session_token: None,
        }
    }

    #[test]
    fn source_reports_provider_key() {
        let s = BedrockSource::new("us-east-1", dummy_creds());
        assert_eq!(s.provider(), "aws_bedrock");
    }

    #[test]
    fn url_uses_control_plane_host_not_runtime() {
        let s = BedrockSource::new("eu-central-1", dummy_creds());
        let url = s.url();
        assert!(url.contains("bedrock.eu-central-1.amazonaws.com/foundation-models"));
        assert!(
            !url.contains("bedrock-runtime"),
            "ListFoundationModels lives on the control-plane host"
        );
    }

    #[test]
    fn url_threads_through_per_region() {
        let s_us = BedrockSource::new("us-east-1", dummy_creds());
        let s_eu = BedrockSource::new("eu-central-1", dummy_creds());
        assert!(s_us.url().contains("us-east-1"));
        assert!(s_eu.url().contains("eu-central-1"));
        assert_ne!(s_us.url(), s_eu.url());
    }
}
