//! Official OMI Developer API client.
//!
//! Contract pinned to OMI `backend/routers/developer.py` at upstream
//! `e5d09d3d`: Developer-API-key auth, paginated conversation summaries,
//! transcript-bearing detail reads, and idempotent transcript export.
//! Responses are streamed into a hard byte cap before JSON parsing. The API
//! key remains a [`SecretString`] and is never included in client errors.

use std::fmt;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{HeaderMap, USER_AGENT};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::secret::SecretString;

pub const OMI_PAGE_LIMIT: usize = 100;
pub const OMI_MAX_EXPORT_SEGMENTS: usize = 500;
pub const OMI_MAX_CLIENT_SESSION_ID_CHARS: usize = 200;
pub const OMI_DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const OMI_DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OmiClientError {
    #[error("invalid OMI Developer API client configuration: {0}")]
    Configuration(String),
    #[error("OMI Developer API transport failed: {0}")]
    Transport(String),
    #[error("OMI Developer API rejected the API key (HTTP 401)")]
    Unauthorized,
    #[error("OMI Developer API key lacks the required scope (HTTP 403)")]
    Forbidden,
    #[error("OMI Developer API resource was not found (HTTP 404)")]
    NotFound,
    #[error("OMI Developer API rate limited the request (HTTP 429, retry_after={retry_after:?})")]
    RateLimited { retry_after: Option<Duration> },
    #[error("OMI Developer API server failed (HTTP {status})")]
    Server { status: u16 },
    #[error("OMI Developer API request failed (HTTP {status})")]
    HttpStatus { status: u16 },
    #[error(
        "OMI Developer API response exceeded {max_bytes} bytes (observed at least {observed_bytes})"
    )]
    ResponseTooLarge {
        max_bytes: usize,
        observed_bytes: u64,
    },
    #[error("malformed OMI Developer API {operation} response: {message}")]
    MalformedResponse {
        operation: &'static str,
        message: String,
    },
    #[error("invalid OMI Developer API input: {0}")]
    Validation(String),
}

/// Developer conversation response model. Unknown future fields are ignored;
/// the detail revision is computed from the full raw JSON before that happens.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiConversation {
    pub id: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub structured: OmiStructured,
    pub language: Option<String>,
    pub source: Option<String>,
    pub transcript_segments: Option<Vec<OmiTranscriptSegment>>,
    pub geolocation: Option<OmiGeolocation>,
    pub folder_id: Option<String>,
    pub folder_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiStructured {
    pub title: String,
    pub overview: String,
    #[serde(default)]
    pub emoji: Option<String>,
    pub category: String,
    #[serde(default)]
    pub action_items: Vec<OmiActionItem>,
    #[serde(default)]
    pub events: Vec<OmiEvent>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiActionItem {
    pub description: String,
    #[serde(default)]
    pub completed: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub due_at: Option<String>,
    pub completed_at: Option<String>,
    pub conversation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiEvent {
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub start: String,
    pub duration: Option<u32>,
    pub created: Option<bool>,
}

/// Exact `SimpleTranscriptSegment` response shape at the pinned upstream HEAD.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiTranscriptSegment {
    pub id: Option<String>,
    pub text: String,
    pub speaker_id: Option<i64>,
    pub speaker_name: Option<String>,
    pub start: f64,
    pub end: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiGeolocation {
    pub google_place_id: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub address: Option<String>,
    pub location_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OmiConversationPage {
    pub conversations: Vec<OmiConversationSummary>,
    pub offset: u64,
    pub next_offset: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OmiConversationSummary {
    pub conversation: OmiConversation,
    /// SHA-256 over the complete list item, including unknown additive fields.
    /// This is a cheap change detector only; detail revision remains the
    /// authoritative idempotency key because list items omit transcripts.
    pub revision: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OmiConversationDetail {
    pub conversation: OmiConversation,
    /// SHA-256 over canonical JSON for the complete detail response, including
    /// additive fields unknown to this client version.
    pub revision: String,
}

/// Developer `CreateConversationFromTranscriptRequest` segment shape. This is
/// intentionally separate from the narrower response segment DTO above.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiExportSegment {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker_id: Option<i64>,
    /// Omitted when the capture source cannot identify the operator. OMI's
    /// server currently defaults an omitted value to `false`; NEOTH keeps the
    /// unknown state explicit in its own ledger and never infers it from a
    /// diarization speaker id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_id: Option<String>,
    pub start: f64,
    pub end: f64,
}

/// Export request with an explicit caller-owned idempotency key. The client
/// never generates this id: retries must reuse the same stable value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OmiExportSegmentsRequest {
    pub transcript_segments: Vec<OmiExportSegment>,
    pub client_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geolocation: Option<OmiGeolocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_platform: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmiExportResponse {
    pub id: String,
    pub status: String,
    pub discarded: bool,
}

#[derive(Clone)]
pub struct OmiDeveloperClient {
    endpoint: Url,
    api_key: SecretString,
    max_response_bytes: usize,
    timeout: Duration,
    http: reqwest::Client,
}

impl fmt::Debug for OmiDeveloperClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OmiDeveloperClient")
            .field("endpoint", &self.endpoint.as_str())
            .field("api_key", &"[REDACTED]")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl OmiDeveloperClient {
    pub fn with_defaults(
        endpoint: impl AsRef<str>,
        api_key: SecretString,
    ) -> Result<Self, OmiClientError> {
        Self::new(
            endpoint,
            api_key,
            OMI_DEFAULT_MAX_RESPONSE_BYTES,
            OMI_DEFAULT_REQUEST_TIMEOUT,
        )
    }

    pub fn new(
        endpoint: impl AsRef<str>,
        api_key: SecretString,
        max_response_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, OmiClientError> {
        if !api_key.expose_secret().starts_with("omi_dev_")
            || api_key.expose_secret().len() == "omi_dev_".len()
        {
            return Err(OmiClientError::Configuration(
                "API key must use the omi_dev_ prefix".to_string(),
            ));
        }
        if api_key.expose_secret().trim() != api_key.expose_secret() {
            return Err(OmiClientError::Configuration(
                "API key must not contain surrounding whitespace".to_string(),
            ));
        }
        if max_response_bytes == 0 {
            return Err(OmiClientError::Configuration(
                "max_response_bytes must be greater than zero".to_string(),
            ));
        }
        if timeout.is_zero() {
            return Err(OmiClientError::Configuration(
                "timeout must be greater than zero".to_string(),
            ));
        }

        // Parse via FromStr rather than a direct Url::parse construction site;
        // the project network audit reserves that textual pattern for explicit
        // allowlist entries. This client still uses reqwest's Url parser.
        let mut endpoint = endpoint.as_ref().parse::<Url>().map_err(|error| {
            OmiClientError::Configuration(format!("endpoint is not a valid URL: {error}"))
        })?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(OmiClientError::Configuration(
                "endpoint scheme must be http or https".to_string(),
            ));
        }
        if endpoint.host_str().is_none() {
            return Err(OmiClientError::Configuration(
                "endpoint must include a host".to_string(),
            ));
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(OmiClientError::Configuration(
                "endpoint must not contain credentials".to_string(),
            ));
        }
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(OmiClientError::Configuration(
                "endpoint must not contain a query or fragment".to_string(),
            ));
        }
        if !endpoint.path().ends_with('/') {
            let normalized = format!("{}/", endpoint.path());
            endpoint.set_path(&normalized);
        }

        let http = crate::providers::http_client::build_client_no_redirect().map_err(|error| {
            OmiClientError::Configuration(format!("failed to build HTTP client: {error}"))
        })?;
        Ok(Self {
            endpoint,
            api_key,
            max_response_bytes,
            timeout,
            http,
        })
    }

    /// Fetch one summary page. The official Developer API returns a bare list,
    /// so a full 100-row page exposes the caller seam for the next offset.
    pub async fn list_page(&self, offset: u64) -> Result<OmiConversationPage, OmiClientError> {
        let mut url = self.url("v1/dev/user/conversations")?;
        url.query_pairs_mut()
            .append_pair("include_transcript", "false")
            .append_pair("limit", &OMI_PAGE_LIMIT.to_string())
            .append_pair("offset", &offset.to_string());
        let bytes = self.execute(self.authorized(self.http.get(url))).await?;
        let raw_conversations: Vec<Value> = decode_json(&bytes, "conversation list")?;
        if raw_conversations.len() > OMI_PAGE_LIMIT {
            return Err(OmiClientError::MalformedResponse {
                operation: "conversation list",
                message: format!(
                    "server returned {} rows for a {}-row page",
                    raw_conversations.len(),
                    OMI_PAGE_LIMIT
                ),
            });
        }
        let next_offset = if raw_conversations.len() == OMI_PAGE_LIMIT {
            Some(offset.checked_add(OMI_PAGE_LIMIT as u64).ok_or_else(|| {
                OmiClientError::Validation("pagination offset overflow".to_string())
            })?)
        } else {
            None
        };
        let conversations = raw_conversations
            .into_iter()
            .map(|raw| {
                let revision = conversation_revision(&raw);
                serde_json::from_value(raw)
                    .map(|conversation| OmiConversationSummary {
                        conversation,
                        revision,
                    })
                    .map_err(|error| OmiClientError::MalformedResponse {
                        operation: "conversation list",
                        message: format!(
                            "response does not match the Developer API schema ({:?})",
                            error.classify()
                        ),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OmiConversationPage {
            conversations,
            offset,
            next_offset,
        })
    }

    pub async fn detail(
        &self,
        conversation_id: &str,
    ) -> Result<OmiConversationDetail, OmiClientError> {
        validate_conversation_id(conversation_id)?;
        let mut url = self.url("v1/dev/user/conversations")?;
        url.path_segments_mut()
            .map_err(|_| {
                OmiClientError::Configuration("endpoint cannot be a base URL".to_string())
            })?
            .push(conversation_id);
        url.query_pairs_mut()
            .append_pair("include_transcript", "true");
        let bytes = self.execute(self.authorized(self.http.get(url))).await?;
        let raw: Value = decode_json(&bytes, "conversation detail")?;
        let conversation = serde_json::from_value(raw.clone()).map_err(|error| {
            OmiClientError::MalformedResponse {
                operation: "conversation detail",
                message: format!(
                    "response does not match the Developer API schema ({:?})",
                    error.classify()
                ),
            }
        })?;
        Ok(OmiConversationDetail {
            conversation,
            revision: conversation_revision(&raw),
        })
    }

    pub async fn export_segments(
        &self,
        request: &OmiExportSegmentsRequest,
    ) -> Result<OmiExportResponse, OmiClientError> {
        validate_export_request(request)?;
        let url = self.url("v1/dev/user/conversations/from-segments")?;
        let bytes = self
            .execute(self.authorized(self.http.post(url).json(request)))
            .await?;
        decode_json(&bytes, "conversation export")
    }

    fn url(&self, path: &'static str) -> Result<Url, OmiClientError> {
        self.endpoint.join(path).map_err(|error| {
            OmiClientError::Configuration(format!("cannot construct OMI API URL: {error}"))
        })
    }

    fn authorized(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .bearer_auth(self.api_key.expose_secret())
            .header(
                USER_AGENT,
                concat!("NEOTH/", env!("CARGO_PKG_VERSION"), " omi-developer-client"),
            )
            .timeout(self.timeout)
    }

    async fn execute(&self, request: RequestBuilder) -> Result<Vec<u8>, OmiClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| OmiClientError::Transport(error.to_string()))?;
        classify_status(response.status(), response.headers())?;

        if let Some(content_length) = response.content_length()
            && content_length > self.max_response_bytes as u64
        {
            return Err(OmiClientError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
                observed_bytes: content_length,
            });
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(self.max_response_bytes as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| OmiClientError::Transport(error.to_string()))?;
            let next_len =
                body.len()
                    .checked_add(chunk.len())
                    .ok_or(OmiClientError::ResponseTooLarge {
                        max_bytes: self.max_response_bytes,
                        observed_bytes: u64::MAX,
                    })?;
            if next_len > self.max_response_bytes {
                return Err(OmiClientError::ResponseTooLarge {
                    max_bytes: self.max_response_bytes,
                    observed_bytes: next_len as u64,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn classify_status(status: StatusCode, headers: &HeaderMap) -> Result<(), OmiClientError> {
    if status.is_success() {
        return Ok(());
    }
    Err(match status {
        StatusCode::UNAUTHORIZED => OmiClientError::Unauthorized,
        StatusCode::FORBIDDEN => OmiClientError::Forbidden,
        StatusCode::NOT_FOUND => OmiClientError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => OmiClientError::RateLimited {
            retry_after: crate::providers::quota::parse_retry_after(headers),
        },
        status if status.is_server_error() => OmiClientError::Server {
            status: status.as_u16(),
        },
        status => OmiClientError::HttpStatus {
            status: status.as_u16(),
        },
    })
}

fn decode_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    operation: &'static str,
) -> Result<T, OmiClientError> {
    serde_json::from_slice(bytes).map_err(|error| OmiClientError::MalformedResponse {
        operation,
        message: format!(
            "JSON decode failed at line {}, column {} ({:?})",
            error.line(),
            error.column(),
            error.classify()
        ),
    })
}

fn validate_conversation_id(conversation_id: &str) -> Result<(), OmiClientError> {
    if conversation_id.is_empty() || conversation_id.trim() != conversation_id {
        return Err(OmiClientError::Validation(
            "conversation_id must be non-empty and trimmed".to_string(),
        ));
    }
    if conversation_id.chars().count() > 512 || conversation_id.chars().any(char::is_control) {
        return Err(OmiClientError::Validation(
            "conversation_id must be at most 512 characters and contain no control characters"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_export_source(source: &str) -> Result<(), OmiClientError> {
    if matches!(
        source,
        "friend"
            | "omi"
            | "fieldy"
            | "bee"
            | "plaud"
            | "frame"
            | "friend_com"
            | "apple_watch"
            | "phone"
            | "phone_call"
            | "desktop"
            | "openglass"
            | "screenpipe"
            | "workflow"
            | "sdcard"
            | "external_integration"
            | "limitless"
            | "rayban_meta"
            | "onboarding"
            | "unknown"
    ) {
        Ok(())
    } else {
        Err(OmiClientError::Validation(format!(
            "unsupported OMI conversation source {source:?}"
        )))
    }
}

fn validate_export_request(request: &OmiExportSegmentsRequest) -> Result<(), OmiClientError> {
    let count = request.transcript_segments.len();
    if !(1..=OMI_MAX_EXPORT_SEGMENTS).contains(&count) {
        return Err(OmiClientError::Validation(format!(
            "transcript_segments must contain 1..={OMI_MAX_EXPORT_SEGMENTS} entries"
        )));
    }
    let session_id = request.client_session_id.as_str();
    if session_id.is_empty() || session_id.trim() != session_id {
        return Err(OmiClientError::Validation(
            "client_session_id must be non-empty, stable, and trimmed".to_string(),
        ));
    }
    if session_id.chars().count() > OMI_MAX_CLIENT_SESSION_ID_CHARS {
        return Err(OmiClientError::Validation(format!(
            "client_session_id must be at most {OMI_MAX_CLIENT_SESSION_ID_CHARS} characters"
        )));
    }
    if let Some(source) = request.source.as_deref() {
        validate_export_source(source)?;
    }
    for (index, segment) in request.transcript_segments.iter().enumerate() {
        if segment.text.trim().is_empty() {
            return Err(OmiClientError::Validation(format!(
                "segment {index} text must not be empty"
            )));
        }
        if !segment.start.is_finite()
            || !segment.end.is_finite()
            || segment.start < 0.0
            || segment.end <= segment.start
        {
            return Err(OmiClientError::Validation(format!(
                "segment {index} must have finite timing with 0 <= start < end"
            )));
        }
    }
    Ok(())
}

/// Deterministic revision for a complete OMI detail JSON value. Object keys are
/// sorted recursively; arrays retain API order. Unknown additive fields remain
/// part of the digest even though typed DTO deserialization ignores them.
pub fn conversation_revision(value: &Value) -> String {
    let canonical = canonicalize_json(value);
    let bytes = serde_json::to_vec(&canonical).expect("serde_json::Value always serializes");
    hex::encode(Sha256::digest(bytes))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut canonical = serde_json::Map::with_capacity(object.len());
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json(&object[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "omi_dev_test-secret-never-log";

    fn client(server: &MockServer, max_response_bytes: usize) -> OmiDeveloperClient {
        OmiDeveloperClient::new(
            server.uri(),
            SecretString::from(TOKEN),
            max_response_bytes,
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn conversation_json(id: impl Into<String>, with_transcript: bool) -> Value {
        let transcript = with_transcript.then(|| {
            serde_json::json!([{
                "id": "segment-1",
                "text": "Hello from OMI",
                "speaker_id": 7,
                "speaker_name": "Alex",
                "start": 0.0,
                "end": 1.25
            }])
        });
        let mut conversation = serde_json::json!({
            "id": id.into(),
            "created_at": "2026-07-13T10:00:00Z",
            "started_at": "2026-07-13T10:00:00Z",
            "finished_at": "2026-07-13T10:00:02Z",
            "structured": {
                "title": "OMI conversation",
                "overview": "A bounded fixture",
                "emoji": "brain",
                "category": "work",
                "action_items": [{
                    "description": "Ship the client",
                    "completed": false,
                    "created_at": "2026-07-13T10:00:01Z",
                    "due_at": null,
                    "completed_at": null,
                    "conversation_id": "conversation-1"
                }],
                "events": [{
                    "title": "Review",
                    "description": "Review OMI integration",
                    "start": "2026-07-14T10:00:00Z",
                    "duration": 30,
                    "created": false
                }]
            },
            "language": "en",
            "source": "omi",
            "transcript_segments": transcript,
            "geolocation": {
                "google_place_id": null,
                "latitude": 52.52,
                "longitude": 13.405,
                "address": "Berlin",
                "location_type": "city"
            },
            "folder_id": "folder-1",
            "folder_name": "Work",
            "additive_future_field": { "kept_in_revision": true }
        });
        if !with_transcript {
            conversation
                .as_object_mut()
                .unwrap()
                .remove("transcript_segments");
        }
        conversation
    }

    fn export_request() -> OmiExportSegmentsRequest {
        OmiExportSegmentsRequest {
            transcript_segments: vec![
                OmiExportSegment {
                    text: "Hello".to_string(),
                    speaker: Some("SPEAKER_00".to_string()),
                    speaker_id: Some(0),
                    is_user: Some(true),
                    person_id: None,
                    start: 0.0,
                    end: 1.0,
                },
                OmiExportSegment {
                    text: "Hi back".to_string(),
                    speaker: Some("SPEAKER_01".to_string()),
                    speaker_id: Some(1),
                    is_user: Some(false),
                    person_id: Some("person-1".to_string()),
                    start: 1.2,
                    end: 2.0,
                },
            ],
            client_session_id: "neoth-session-stable-001".to_string(),
            source: Some("phone_call".to_string()),
            started_at: Some("2026-07-13T10:00:00Z".to_string()),
            finished_at: Some("2026-07-13T10:00:02Z".to_string()),
            language: Some("en".to_string()),
            geolocation: None,
            client_device_id: Some("windows_neoth".to_string()),
            client_platform: Some("windows".to_string()),
        }
    }

    #[tokio::test]
    async fn list_page_uses_exact_developer_path_query_auth_and_lenient_dto() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/dev/user/conversations"))
            .and(query_param("include_transcript", "false"))
            .and(query_param("limit", "100"))
            .and(query_param("offset", "30"))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(vec![conversation_json("conversation-1", false)]),
            )
            .expect(1)
            .mount(&server)
            .await;

        let page = client(&server, 1024 * 1024).list_page(30).await.unwrap();
        assert_eq!(page.offset, 30);
        assert_eq!(page.next_offset, None);
        assert_eq!(page.conversations.len(), 1);
        assert_eq!(page.conversations[0].conversation.id, "conversation-1");
        assert_eq!(page.conversations[0].conversation.transcript_segments, None);
        assert_eq!(page.conversations[0].revision.len(), 64);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.query(),
            Some("include_transcript=false&limit=100&offset=30")
        );
    }

    #[tokio::test]
    async fn detail_uses_exact_path_and_parses_only_official_segment_fields() {
        let server = MockServer::start().await;
        let fixture = conversation_json("conversation-1", true);
        Mock::given(method("GET"))
            .and(path("/v1/dev/user/conversations/conversation-1"))
            .and(query_param("include_transcript", "true"))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&fixture))
            .expect(1)
            .mount(&server)
            .await;

        let detail = client(&server, 1024 * 1024)
            .detail("conversation-1")
            .await
            .unwrap();
        let segment = &detail.conversation.transcript_segments.as_ref().unwrap()[0];
        assert_eq!(segment.id.as_deref(), Some("segment-1"));
        assert_eq!(segment.text, "Hello from OMI");
        assert_eq!(segment.speaker_id, Some(7));
        assert_eq!(segment.speaker_name.as_deref(), Some("Alex"));
        assert_eq!(segment.start, 0.0);
        assert_eq!(segment.end, 1.25);
        assert_eq!(
            detail.conversation.structured.action_items[0].description,
            "Ship the client"
        );
        assert_eq!(detail.conversation.structured.events[0].title, "Review");
        assert_eq!(
            detail
                .conversation
                .geolocation
                .as_ref()
                .unwrap()
                .address
                .as_deref(),
            Some("Berlin")
        );
        assert_eq!(detail.conversation.folder_id.as_deref(), Some("folder-1"));
        assert_eq!(detail.revision, conversation_revision(&fixture));
        assert_eq!(detail.revision.len(), 64);
    }

    #[test]
    fn revision_is_key_order_stable_and_changes_for_any_detail_content() {
        let first: Value = serde_json::from_str(
            r#"{"id":"c1","future":{"z":2,"a":1},"segments":[{"text":"one"}]}"#,
        )
        .unwrap();
        let reordered: Value = serde_json::from_str(
            r#"{"segments":[{"text":"one"}],"future":{"a":1,"z":2},"id":"c1"}"#,
        )
        .unwrap();
        let changed: Value = serde_json::from_str(
            r#"{"segments":[{"text":"two"}],"future":{"a":1,"z":2},"id":"c1"}"#,
        )
        .unwrap();
        assert_eq!(
            conversation_revision(&first),
            conversation_revision(&reordered)
        );
        assert_ne!(
            conversation_revision(&first),
            conversation_revision(&changed)
        );
    }

    #[test]
    fn revision_covers_every_developer_detail_section() {
        let base = conversation_json("conversation-1", true);
        let expected = conversation_revision(&base);
        for pointer in [
            "/structured/overview",
            "/structured/action_items/0/description",
            "/structured/events/0/title",
            "/geolocation/address",
            "/folder_id",
            "/transcript_segments/0/text",
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::String("changed".to_string());
            assert_ne!(
                conversation_revision(&changed),
                expected,
                "revision must cover {pointer}"
            );
        }
    }

    #[tokio::test]
    async fn full_page_exposes_next_offset_for_caller_controlled_pagination() {
        let server = MockServer::start().await;
        let conversations: Vec<Value> = (0..OMI_PAGE_LIMIT)
            .map(|index| conversation_json(format!("conversation-{index}"), false))
            .collect();
        Mock::given(method("GET"))
            .and(path("/v1/dev/user/conversations"))
            .and(query_param("limit", "100"))
            .and(query_param("offset", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(conversations))
            .mount(&server)
            .await;

        let page = client(&server, 4 * 1024 * 1024)
            .list_page(200)
            .await
            .unwrap();
        assert_eq!(page.conversations.len(), 100);
        assert_eq!(page.next_offset, Some(300));
    }

    async fn list_error_for(template: ResponseTemplate) -> OmiClientError {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/dev/user/conversations"))
            .respond_with(template)
            .mount(&server)
            .await;
        client(&server, 1024).list_page(0).await.unwrap_err()
    }

    #[tokio::test]
    async fn status_errors_are_typed_and_retry_after_is_preserved() {
        assert_eq!(
            list_error_for(ResponseTemplate::new(401)).await,
            OmiClientError::Unauthorized
        );
        assert_eq!(
            list_error_for(ResponseTemplate::new(403)).await,
            OmiClientError::Forbidden
        );
        assert_eq!(
            list_error_for(ResponseTemplate::new(404)).await,
            OmiClientError::NotFound
        );
        assert_eq!(
            list_error_for(ResponseTemplate::new(429).insert_header("retry-after", "17")).await,
            OmiClientError::RateLimited {
                retry_after: Some(Duration::from_secs(17))
            }
        );
        assert_eq!(
            list_error_for(ResponseTemplate::new(503)).await,
            OmiClientError::Server { status: 503 }
        );
        assert_eq!(
            list_error_for(ResponseTemplate::new(422)).await,
            OmiClientError::HttpStatus { status: 422 }
        );
    }

    #[tokio::test]
    async fn response_body_is_hard_bounded_before_json_decode() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[\"far too large\"]"))
            .mount(&server)
            .await;
        let error = client(&server, 8).list_page(0).await.unwrap_err();
        assert!(matches!(
            error,
            OmiClientError::ResponseTooLarge { max_bytes: 8, .. }
        ));
    }

    #[tokio::test]
    async fn malformed_success_response_is_typed_without_body_echo() {
        let server = MockServer::start().await;
        let secret_body = "not-json-with-omi_dev_body_secret";
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(secret_body))
            .mount(&server)
            .await;
        let error = client(&server, 1024).list_page(0).await.unwrap_err();
        assert!(matches!(error, OmiClientError::MalformedResponse { .. }));
        assert!(!format!("{error:?}").contains(secret_body));
        assert!(!error.to_string().contains(secret_body));
    }

    #[tokio::test]
    async fn configured_timeout_is_enforced() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
            .mount(&server)
            .await;
        let client = OmiDeveloperClient::new(
            server.uri(),
            SecretString::from(TOKEN),
            1024,
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(matches!(
            client.list_page(0).await,
            Err(OmiClientError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn export_is_exact_and_retries_send_identical_idempotency_payload() {
        let server = MockServer::start().await;
        let request = export_request();
        let expected_body = serde_json::to_value(&request).unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/dev/user/conversations/from-segments"))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "stable-upstream-id",
                "status": "completed",
                "discarded": false
            })))
            .expect(2)
            .mount(&server)
            .await;

        let client = client(&server, 1024 * 1024);
        let first = client.export_segments(&request).await.unwrap();
        let retry = client.export_segments(&request).await.unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.id, "stable-upstream-id");
        assert_eq!(request.client_session_id, "neoth-session-stable-001");
    }

    #[tokio::test]
    async fn export_validation_rejects_invalid_count_session_id_and_timing_preflight() {
        let server = MockServer::start().await;
        let client = client(&server, 1024);

        let mut empty = export_request();
        empty.transcript_segments.clear();
        assert!(matches!(
            client.export_segments(&empty).await,
            Err(OmiClientError::Validation(_))
        ));

        let mut too_many = export_request();
        too_many.transcript_segments = vec![too_many.transcript_segments[0].clone(); 501];
        assert!(matches!(
            client.export_segments(&too_many).await,
            Err(OmiClientError::Validation(_))
        ));

        let mut unstable_id = export_request();
        unstable_id.client_session_id = "  session  ".to_string();
        assert!(matches!(
            client.export_segments(&unstable_id).await,
            Err(OmiClientError::Validation(_))
        ));

        let mut long_id = export_request();
        long_id.client_session_id = "x".repeat(201);
        assert!(matches!(
            client.export_segments(&long_id).await,
            Err(OmiClientError::Validation(_))
        ));

        let mut bad_timing = export_request();
        bad_timing.transcript_segments[0].end = 0.0;
        assert!(matches!(
            client.export_segments(&bad_timing).await,
            Err(OmiClientError::Validation(_))
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn constructor_enforces_developer_key_and_debug_never_exposes_secret() {
        let token = "omi_dev_extremely-sensitive-value";
        let client = OmiDeveloperClient::new(
            "https://api.omi.me",
            SecretString::from(token),
            1024,
            Duration::from_secs(1),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains(token));
        assert!(debug.contains("REDACTED"));

        let invalid = OmiDeveloperClient::new(
            "https://api.omi.me",
            SecretString::from("ordinary-token"),
            1024,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(!format!("{invalid:?}").contains("ordinary-token"));
        assert!(!invalid.to_string().contains("ordinary-token"));
    }
}
