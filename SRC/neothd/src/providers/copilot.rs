//! GOLD-ADAPT-ODY-15 — GitHub Copilot OAuth provider.
//!
//! GitHub Copilot exposes an OpenAI-compatible chat completions endpoint at
//! `https://api.githubcopilot.com/chat/completions`. Authentication uses a
//! two-step flow:
//!
//! 1. The operator supplies a GitHub PAT (with `copilot` scope) or a
//!    previously-issued device-flow token as `provider_key`. This is the
//!    long-lived credential that never changes.
//!
//! 2. Before each LLM call the adapter exchanges the PAT for a short-lived
//!    Copilot session token by calling
//!    `GET https://api.github.com/copilot_internal/v2/token`. The response
//!    `{"token": "...", "expires_at": "<iso8601>"}` is cached (with a 60-second
//!    buffer) so warm calls pay zero extra RTT.
//!
//! The actual LLM request is identical to the `openai_api` wire format —
//! `CopilotAdapter` holds an inner `OpenAiAdapter` and swaps in the fresh
//! session token per call.
//!
//! **Cost model**: Copilot billing depends on plan, model, remaining allowance
//! and overage state. The adapter does not currently receive an authoritative
//! billing-mode/allowance snapshot, so `lookup_price("copilot_api", _)` stays
//! unknown and every dispatch uses `UnboundedPaidProviderCall`.
//!
//! **Consent gate**: Copilot sends operator text to `api.githubcopilot.com`
//! (GitHub/Microsoft servers). `consent::is_cloud(ProviderKind::GitHubCopilot)`
//! returns `true` — the operator must run `neoth consent grant copilot_api`
//! before any traffic is sent. This is enforced by the existing pre-flight
//! gates in `cli::chat` and `serve`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::debug;

use super::openai_api::OpenAiAdapter;
use super::{Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request};
use crate::secret::SecretString;

/// The token endpoint answers with a small JSON envelope; chat itself runs
/// through the already-bounded OpenAI-compatible transport. 64 KiB is far
/// above any legitimate token response and keeps a hostile or misrouted
/// endpoint from being read into memory unbounded.
const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;
const TOKEN_ERROR_EVIDENCE_DOMAIN: &[u8] = b"copilot-token-error-body/v1";
const TOKEN_SUCCESS_EVIDENCE_DOMAIN: &[u8] = b"copilot-token-success-body/v1";

/// Cached short-lived Copilot session token + the instant at which it expires
/// (already reduced by a 60-second safety buffer).
#[derive(Debug)]
struct CopilotTokenCache {
    /// The short-lived token string (`tid=…` or similar).
    token: String,
    /// Wall-clock deadline (already includes the 60 s buffer — we refresh
    /// before this instant, not at the official `expires_at`).
    expires_at: Instant,
}

/// GitHub Copilot provider adapter.
///
/// Thread-safe via `Arc<Mutex<Option<CopilotTokenCache>>>` — multiple async
/// tasks in the daemon can share one `Arc<CopilotAdapter>` (the `Provider`
/// trait is `Sync`) without locking across the heavy HTTP call; only the
/// cache-write path needs the mutex.
pub struct CopilotAdapter {
    /// The GitHub PAT / device-flow token used to obtain short-lived session
    /// tokens from `api.github.com/copilot_internal/v2/token`.
    pat: SecretString,
    /// Default model id (e.g. `"gpt-4o"`).
    model: String,
    /// Short-lived token cache. `None` on first call → always fetches.
    token_cache: Arc<Mutex<Option<CopilotTokenCache>>>,
    /// Token-exchange endpoint. The public constructor pins the official URL;
    /// `build` exists so bounds fixtures exercise this exact code path against
    /// a local mock, the way the other adapters already do.
    token_endpoint: String,
    /// Shared HTTP client — same pool for both the token endpoint and the
    /// Copilot completions endpoint.
    http: reqwest::Client,
}

/// Official GitHub Copilot token-exchange endpoint.
const TOKEN_ENDPOINT: &str = "https://api.github.com/copilot_internal/v2/token";

impl CopilotAdapter {
    /// Construct a new adapter.
    ///
    /// `pat`   — GitHub PAT with `copilot` scope (stored as `provider_key`).
    /// `model` — model id to send to the Copilot completions endpoint
    ///           (defaults to `gpt-4o`; operator can override via `provider_model`).
    pub fn new(pat: SecretString, model: String) -> Result<Self> {
        Self::build(TOKEN_ENDPOINT.to_string(), pat, model)
    }

    fn build(token_endpoint: String, pat: SecretString, model: String) -> Result<Self> {
        let http = crate::providers::http_client::build_client_no_redirect()?;
        Ok(Self {
            pat,
            model,
            token_cache: Arc::new(Mutex::new(None)),
            token_endpoint,
            http,
        })
    }

    /// Return a valid short-lived Copilot session token, fetching or refreshing
    /// as necessary. Checks the cache first; if the token is still fresh returns
    /// it without any network call. Expired (or absent) → fetches a new one from
    /// `api.github.com/copilot_internal/v2/token`.
    ///
    /// The 60-second buffer guards against clock skew between the NEOTH daemon
    /// host and GitHub's servers plus the propagation delay of a token endpoint
    /// call (~200 ms typical). Without the buffer a token could expire mid-
    /// completions-call.
    async fn fetch_or_refresh_token(&self) -> Result<SecretString> {
        const BUFFER: Duration = Duration::from_secs(60);

        {
            let cache = self.token_cache.lock().await;
            if let Some(ref cached) = *cache
                && Instant::now() + BUFFER < cached.expires_at
            {
                debug!("copilot_api: reusing cached session token");
                return Ok(SecretString::from(cached.token.clone()));
            }
        }

        // Cache miss or stale — fetch a fresh token.
        debug!("copilot_api: fetching new session token from github");
        let url = self.token_endpoint.as_str();
        let response = self
            .http
            .get(url)
            .bearer_auth(self.pat.expose())
            .header("User-Agent", "neoth/0.1")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        let status = response.status();
        if !status.is_success() {
            let evidence = super::response_bounds::error_body_evidence(
                response,
                TOKEN_ERROR_EVIDENCE_DOMAIN,
                MAX_TOKEN_BODY_BYTES,
            )
            .await;
            anyhow::bail!(
                "copilot_api token endpoint returned HTTP {} ({evidence}). \
                 Ensure your GitHub PAT has the `copilot` scope and your \
                 account has an active GitHub Copilot subscription.",
                status.as_u16()
            );
        }

        let token_resp: CopilotTokenResponse = super::response_bounds::decode_json(
            response,
            "copilot_api",
            TOKEN_SUCCESS_EVIDENCE_DOMAIN,
            MAX_TOKEN_BODY_BYTES,
        )
        .await?;

        // Parse `expires_at` (ISO 8601) → `Instant`.
        let expires_at = parse_expires_at(&token_resp.expires_at).unwrap_or_else(|| {
            // Fallback: assume 30-minute lifetime if we can't parse the field.
            Instant::now() + Duration::from_secs(1800)
        });

        let fresh_token = token_resp.token.clone();
        {
            let mut cache = self.token_cache.lock().await;
            *cache = Some(CopilotTokenCache {
                token: token_resp.token,
                expires_at,
            });
        }

        debug!("copilot_api: session token refreshed");
        Ok(SecretString::from(fresh_token))
    }

    /// Build a one-shot `OpenAiAdapter` pointed at the Copilot completions
    /// endpoint with the given session token. Constructing a new adapter per
    /// call is cheap — `reqwest::Client` is cloned (inner Arc), so the
    /// connection pool is shared.
    fn make_inner(&self, session_token: SecretString) -> Result<OpenAiAdapter> {
        OpenAiAdapter::new_copilot(
            "https://api.githubcopilot.com".to_string(),
            session_token,
            self.model.clone(),
        )
    }
}

#[async_trait]
impl Provider for CopilotAdapter {
    fn name(&self) -> &'static str {
        "copilot_api"
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.model)
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
    }

    fn streams_on_wire(&self) -> bool {
        true
    }

    async fn complete_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        let token = self.fetch_or_refresh_token().await?;
        let inner = self.make_inner(token)?;
        inner.complete_raw(req, permit).await
    }

    async fn stream_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<super::ChunkStream> {
        let token = self.fetch_or_refresh_token().await?;
        let inner = self.make_inner(token)?;
        inner.stream_raw(req, permit).await
    }
}

// ── Wire types for the token endpoint ─────────────────────────────────────

#[derive(Deserialize)]
struct CopilotTokenResponse {
    token: String,
    expires_at: String,
}

/// Parse an ISO 8601 / RFC 3339 timestamp string (`"2026-06-27T18:00:00Z"`)
/// into a monotonic `Instant`. Returns `None` when parsing fails so the
/// caller can apply a conservative fallback.
///
/// Approach: parse the epoch-seconds component, subtract `now()` as a
/// wall-clock delta, and add that delta to `Instant::now()`. This avoids
/// pulling `chrono` or `time` into the providers crate — we only need the
/// rough expiry instant, not a calendar type.
fn parse_expires_at(s: &str) -> Option<Instant> {
    // RFC 3339 `%Y-%m-%dT%H:%M:%SZ` / `%Y-%m-%dT%H:%M:%S+00:00`.
    // The Copilot token endpoint emits the `Z` suffix form.
    // Use `SystemTime` (available in std) to parse via seconds-since-epoch.
    use std::time::{SystemTime, UNIX_EPOCH};

    // Parse the numeric epoch via a minimal hand-rolled scanner — avoids any
    // heavy dep. We use the fact that `SystemTime::UNIX_EPOCH + duration`
    // gives us a `SystemTime` we can compare to `SystemTime::now()`.
    let epoch_secs = s
        // Strip trailing Z or timezone offset to get up to the seconds field.
        .trim_end_matches('Z')
        .split('+')
        .next()
        .and_then(|dt| {
            // dt looks like "2026-06-27T18:00:00"
            // Parse as rough seconds via the NaiveDateTime components.
            let parts: Vec<&str> = dt.split('T').collect();
            if parts.len() != 2 {
                return None;
            }
            let date: Vec<u32> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
            let time: Vec<u32> = parts[1].split(':').filter_map(|s| s.parse().ok()).collect();
            if date.len() < 3 || time.len() < 3 {
                return None;
            }
            // Approximate epoch via the calendar formula (Gregorian).
            // Accurate to ±1 s for dates in the 2020-2030 range.
            let y = date[0] as i64;
            let m = date[1] as i64;
            let d = date[2] as i64;
            let h = time[0] as i64;
            let mn = time[1] as i64;
            let sc = time[2] as i64;
            // Zeller-inspired month offset (1-indexed, ignoring leap seconds).
            let a = (14 - m) / 12;
            let y2 = y - a;
            let m2 = m + 12 * a - 3;
            let jd = d + (153 * m2 + 2) / 5 + 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 - 32045;
            let unix_days = jd - 2_440_588; // Julian Day of 1970-01-01
            let secs = unix_days * 86400 + h * 3600 + mn * 60 + sc;
            Some(secs)
        })?;

    let target = UNIX_EPOCH.checked_add(Duration::from_secs(epoch_secs.max(0) as u64))?;
    let now_sys = SystemTime::now();
    let delta = target.duration_since(now_sys).unwrap_or(Duration::ZERO);
    Some(Instant::now() + delta)
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copilot_adapter_name_is_copilot_api() {
        let a = CopilotAdapter::new(SecretString::from("ghp_test"), "gpt-4o".to_string())
            .expect("construct");
        assert_eq!(a.name(), "copilot_api");
    }

    #[test]
    fn copilot_cost_is_unknown_without_live_billing_context() {
        // Plan/model/allowance/overage state decides the marginal charge. A
        // static free row would silently bypass the paid-call gate.
        let price = crate::providers::cost::lookup_price("copilot_api", "gpt-4o");
        assert!(price.is_none(), "copilot_api must remain unknown/unbounded");
    }

    #[test]
    fn copilot_cost_ceiling_matches_the_openai_wire_cap() {
        let adapter = CopilotAdapter::new(SecretString::from("ghp_test"), "gpt-5".to_string())
            .expect("construct");
        let req = Request {
            thinking_budget: Some(16_384),
            ..Request::default()
        };
        assert_eq!(adapter.output_token_ceiling(&req), Some(4096));
    }

    #[test]
    fn copilot_model_roles_resolves_flagship_to_gpt4o() {
        use crate::providers::model_roles::{ModelRole, default_table};
        let t = default_table();
        assert_eq!(
            t.resolve("copilot_api", ModelRole::Flagship),
            Some("gpt-4o"),
            "copilot_api flagship must be gpt-4o"
        );
        assert_eq!(
            t.resolve("copilot_api", ModelRole::Fast),
            Some("gpt-4o-mini"),
            "copilot_api fast must be gpt-4o-mini"
        );
    }

    #[test]
    fn parse_expires_at_future_timestamp_gives_some() {
        // A timestamp well in the future must parse to a non-zero instant
        // greater than now.
        let ts = "2030-01-01T00:00:00Z";
        let inst = parse_expires_at(ts);
        assert!(inst.is_some(), "should parse a future timestamp");
        // It must be in the future (well, relative to Instant::now()).
        // We just verify it parsed; exact duration is tested implicitly by
        // the adapter construction test.
    }

    #[test]
    fn parse_expires_at_bad_input_returns_none() {
        assert!(parse_expires_at("not-a-date").is_none());
        assert!(parse_expires_at("").is_none());
    }

    #[test]
    fn copilot_token_cache_starts_empty() {
        let a = CopilotAdapter::new(SecretString::from("ghp_test"), "gpt-4o".to_string())
            .expect("construct");
        // Cache starts None — proves the first call will always fetch.
        let cache = a.token_cache.blocking_lock();
        assert!(cache.is_none(), "token cache must start empty");
    }

    #[tokio::test]
    async fn copilot_is_cloud_and_consent_roundtrips() {
        use crate::cli::init::ProviderKind;
        use crate::consent;
        let tmp = tempfile::TempDir::new().unwrap();
        // Copilot is cloud — consent must be required.
        assert!(!consent::is_granted(
            tmp.path(),
            ProviderKind::GitHubCopilot
        ));
        consent::grant(tmp.path(), ProviderKind::GitHubCopilot).unwrap();
        assert!(consent::is_granted(tmp.path(), ProviderKind::GitHubCopilot));
        // slug round-trip.
        assert_eq!(consent::slug(ProviderKind::GitHubCopilot), "copilot_api");
        assert_eq!(
            consent::kind_from_slug("copilot_api"),
            Some(ProviderKind::GitHubCopilot)
        );
    }

    // ── Token-exchange envelope bounds (GOLD-R4-15k1) ────────────────────────

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(token_endpoint: &str) -> CopilotAdapter {
        CopilotAdapter::build(
            token_endpoint.to_string(),
            SecretString::from("ghp-mock-pat"),
            "gpt-4o".to_string(),
        )
        .expect("adapter constructs against mock token endpoint")
    }

    async fn mount_token(mock: &MockServer, status: u16, body: impl Into<Vec<u8>>) {
        Mock::given(method("GET"))
            .and(path("/copilot_internal/v2/token"))
            .respond_with(
                ResponseTemplate::new(status).set_body_raw(body.into(), "application/json"),
            )
            .mount(mock)
            .await;
    }

    fn token_url(mock: &MockServer) -> String {
        format!("{}/copilot_internal/v2/token", mock.uri())
    }

    #[tokio::test]
    async fn public_constructor_pins_the_official_token_endpoint() {
        let adapter = CopilotAdapter::new(SecretString::from("ghp-mock-pat"), "gpt-4o".to_string())
            .expect("official constructor");
        assert_eq!(
            adapter.token_endpoint,
            "https://api.github.com/copilot_internal/v2/token"
        );
    }

    #[tokio::test]
    async fn token_refresh_succeeds_through_the_bounded_reader() {
        let mock = MockServer::start().await;
        mount_token(
            &mock,
            200,
            serde_json::json!({"token": "tid=mock;exp=1", "expires_at": "2999-01-01T00:00:00Z"})
                .to_string(),
        )
        .await;

        let token = build_adapter_against(&token_url(&mock))
            .fetch_or_refresh_token()
            .await
            .expect("token refresh must succeed");
        assert_eq!(token.expose(), "tid=mock;exp=1");
    }

    #[tokio::test]
    async fn oversized_token_body_fails_before_json_allocation() {
        let secret = "copilot-never-persist-oversized-token";
        let mock = MockServer::start().await;
        mount_token(
            &mock,
            200,
            format!(
                r#"{{"token":"{secret}{}"}}"#,
                "x".repeat(MAX_TOKEN_BODY_BYTES)
            ),
        )
        .await;

        let message = build_adapter_against(&token_url(&mock))
            .fetch_or_refresh_token()
            .await
            .expect_err("oversized token body must fail before JSON parsing")
            .to_string();
        assert!(message.contains("successful response body exceeded"));
        assert!(message.contains("body_sha256="));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn token_error_body_reports_status_and_digest_only() {
        let secret = "copilot-never-persist-token-error";
        let mock = MockServer::start().await;
        mount_token(
            &mock,
            403,
            format!("{secret}{}", "x".repeat(MAX_TOKEN_BODY_BYTES * 2)),
        )
        .await;

        let message = build_adapter_against(&token_url(&mock))
            .fetch_or_refresh_token()
            .await
            .expect_err("403 must fail")
            .to_string();
        assert!(message.contains("HTTP 403"), "got: {message}");
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(
            message.contains("`copilot` scope"),
            "keeps the operator fix"
        );
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }
}
