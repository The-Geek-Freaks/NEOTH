//! WhatsApp Business Cloud API send surface used by the live Graph adapter and
//! verified inbound webhook reply path.
//!
//! Operator setup:
//!   1. Configure `whatsapp_token` (long-lived system-user access
//!      token) + `whatsapp_phone_id` (the numeric phone-number id
//!      from the Meta console) via `neoth init` or `credentials.yaml`.
//!   2. Run `neoth whatsapp send --to <e164> --message "..."` —
//!      calls `https://graph.facebook.com/v18.0/<phone_id>/messages`
//!      with the configured token.
//!
//! `neoth serve` exposes the loopback webhook listener, verifies Meta's
//! challenge/signature, dispatches inbound messages through the common
//! pipeline, and sends the final reply here. The operator supplies the public
//! HTTPS reverse-proxy endpoint.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

/// Production WhatsApp Business Cloud Graph API base. Split out as a `const` so
/// the send + validate paths share ONE source of truth and tests can override
/// it with a `wiremock` base URL via the `*_at` variants below.
pub const GRAPH_API_BASE: &str = "https://graph.facebook.com/v18.0";

/// Result of a `messages` POST. `id` is WhatsApp's wamid (e.g.
/// `"wamid.HBgL..."`); operators can correlate it with delivery-status
/// events received by the live webhook path.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SendMessageResult {
    pub ok: bool,
    pub wa_id: Option<String>,
    pub message_id: Option<String>,
    pub error: Option<String>,
}

/// POST a text message via the WhatsApp Business Cloud Graph API.
/// `to` is the recipient's phone number in E.164 format (e.g.
/// `"+4915112345678"`); Meta normalises country prefixes server-side.
///
/// Defensive: surfaces Meta's error envelope verbatim in
/// `SendMessageResult::error` when the request fails so the operator
/// sees the real reason (token expired, recipient not opted-in, etc).
pub async fn send_text_message(
    access_token: &SecretString,
    phone_number_id: &str,
    to: &str,
    message: &str,
) -> Result<SendMessageResult> {
    send_text_message_at(GRAPH_API_BASE, access_token, phone_number_id, to, message).await
}

/// Base-URL-injectable core of [`send_text_message`]. The public wrapper passes
/// [`GRAPH_API_BASE`]; the webhook send path + tests point `base_url` at a
/// `wiremock::MockServer` so the "skips API on Deny/DryRun" governance contract
/// is machine-verifiable without touching Meta's network.
pub(crate) async fn send_text_message_at(
    base_url: &str,
    access_token: &SecretString,
    phone_number_id: &str,
    to: &str,
    message: &str,
) -> Result<SendMessageResult> {
    if phone_number_id.is_empty() {
        anyhow::bail!("whatsapp_phone_id is empty — set it in credentials.yaml");
    }
    let url = format!("{base_url}/{phone_number_id}/messages");
    let client = http_client::build_client()?;
    let resp = client
        .post(&url)
        .bearer_auth(access_token.expose())
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "messaging_product": "whatsapp",
                "to": to,
                "type": "text",
                "text": { "body": message },
            }))
            .context("serialize WhatsApp messages payload")?,
        )
        .send()
        .await
        .context("WhatsApp Graph API request")?;
    let status = resp.status();
    let body_text = resp.text().await.context("WhatsApp send response body")?;
    parse_send_response(status.is_success(), &body_text)
}

/// Pure parser — split out so we can unit-test the response shapes
/// without hitting Meta's network.
pub(crate) fn parse_send_response(http_ok: bool, body: &str) -> Result<SendMessageResult> {
    // Try the success shape first; on parse failure or http_ok=false,
    // fall back to the error envelope.
    if http_ok {
        if let Ok(success) = serde_json::from_str::<SuccessBody>(body) {
            let first_msg = success.messages.into_iter().next();
            let first_contact = success.contacts.into_iter().next();
            return Ok(SendMessageResult {
                ok: true,
                wa_id: first_contact.map(|c| c.wa_id),
                message_id: first_msg.map(|m| m.id),
                error: None,
            });
        }
    }
    // Either http error or unrecognised success shape — try error shape.
    if let Ok(err) = serde_json::from_str::<ErrorBody>(body) {
        return Ok(SendMessageResult {
            ok: false,
            wa_id: None,
            message_id: None,
            error: Some(format!(
                "{}: {}",
                err.error.error_type.as_deref().unwrap_or("api_error"),
                err.error.message,
            )),
        });
    }
    // Total surprise — surface the raw body so the operator can debug.
    Ok(SendMessageResult {
        ok: false,
        wa_id: None,
        message_id: None,
        error: Some(format!(
            "unrecognised response (first 200 chars): {}",
            body.chars().take(200).collect::<String>()
        )),
    })
}

/// Result of a phone-number-node GET — validates the access token + phone id
/// WITHOUT sending a message (no recipient, no opt-in needed).
#[derive(Clone, Debug, serde::Serialize)]
pub struct ValidateResult {
    pub ok: bool,
    pub display_phone_number: Option<String>,
    pub verified_name: Option<String>,
    pub error: Option<String>,
}

/// GET the phone-number node to validate that the access token works AND the
/// configured phone id resolves. Behind `neoth channel test whatsapp` — proves
/// the credentials before the operator wonders why a send silently no-ops.
pub async fn validate_token(
    access_token: &SecretString,
    phone_number_id: &str,
) -> Result<ValidateResult> {
    validate_token_at(GRAPH_API_BASE, access_token, phone_number_id).await
}

/// Base-URL-injectable core of [`validate_token`] — see [`send_text_message_at`].
pub(crate) async fn validate_token_at(
    base_url: &str,
    access_token: &SecretString,
    phone_number_id: &str,
) -> Result<ValidateResult> {
    if phone_number_id.is_empty() {
        anyhow::bail!("whatsapp_phone_id is empty — set it in credentials.yaml");
    }
    let url = format!("{base_url}/{phone_number_id}?fields=display_phone_number,verified_name");
    let client = http_client::build_client()?;
    let resp = client
        .get(&url)
        .bearer_auth(access_token.expose())
        .send()
        .await
        .context("WhatsApp Graph API validate request")?;
    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .context("WhatsApp validate response body")?;
    parse_validate_response(status.is_success(), &body_text)
}

/// Pure parser for the phone-number-node response — unit-tested without network.
pub(crate) fn parse_validate_response(http_ok: bool, body: &str) -> Result<ValidateResult> {
    if http_ok {
        if let Ok(node) = serde_json::from_str::<PhoneNode>(body) {
            // A live node returns at least the display number; treat its
            // presence (or a verified name) as proof the token + id are good.
            if node.display_phone_number.is_some() || node.verified_name.is_some() {
                return Ok(ValidateResult {
                    ok: true,
                    display_phone_number: node.display_phone_number,
                    verified_name: node.verified_name,
                    error: None,
                });
            }
        }
    }
    if let Ok(err) = serde_json::from_str::<ErrorBody>(body) {
        return Ok(ValidateResult {
            ok: false,
            display_phone_number: None,
            verified_name: None,
            error: Some(format!(
                "{}: {}",
                err.error.error_type.as_deref().unwrap_or("api_error"),
                err.error.message,
            )),
        });
    }
    Ok(ValidateResult {
        ok: false,
        display_phone_number: None,
        verified_name: None,
        error: Some(format!(
            "unrecognised response (first 200 chars): {}",
            body.chars().take(200).collect::<String>()
        )),
    })
}

#[derive(Deserialize)]
struct PhoneNode {
    #[serde(default)]
    display_phone_number: Option<String>,
    #[serde(default)]
    verified_name: Option<String>,
}

#[derive(Deserialize)]
struct SuccessBody {
    #[serde(default)]
    contacts: Vec<ContactEntry>,
    #[serde(default)]
    messages: Vec<MessageEntry>,
}

#[derive(Deserialize)]
struct ContactEntry {
    #[serde(default)]
    wa_id: String,
}

#[derive(Deserialize)]
struct MessageEntry {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: String,
    #[serde(rename = "type", default)]
    error_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_send_response_extracts_wa_id_and_message_id_on_success() {
        // Real Meta success shape (trimmed).
        let body = r#"{
            "messaging_product": "whatsapp",
            "contacts": [{"input": "+4915112345678", "wa_id": "4915112345678"}],
            "messages": [{"id": "wamid.HBgLNDkxNzU3", "message_status": "accepted"}]
        }"#;
        let r = parse_send_response(true, body).unwrap();
        assert!(r.ok);
        assert_eq!(r.wa_id.as_deref(), Some("4915112345678"));
        assert_eq!(r.message_id.as_deref(), Some("wamid.HBgLNDkxNzU3"));
        assert!(r.error.is_none());
    }

    #[test]
    fn parse_send_response_surfaces_error_envelope() {
        // Real Meta error shape (auth-failure variant).
        let body = r#"{
            "error": {
                "message": "Invalid OAuth access token.",
                "type": "OAuthException",
                "code": 190,
                "fbtrace_id": "AbCd..."
            }
        }"#;
        let r = parse_send_response(false, body).unwrap();
        assert!(!r.ok);
        let err = r.error.unwrap();
        assert!(err.contains("OAuthException"));
        assert!(err.contains("Invalid OAuth"));
    }

    #[test]
    fn parse_send_response_handles_unrecognised_body() {
        // A bad upstream proxy or content-negotiation hiccup might
        // return non-JSON. The parser must not panic; surface the
        // bytes verbatim for operator-side debugging.
        let r = parse_send_response(false, "<html>503</html>").unwrap();
        assert!(!r.ok);
        let err = r.error.unwrap();
        assert!(err.contains("unrecognised"));
        assert!(err.contains("503"));
    }

    #[test]
    fn parse_validate_response_accepts_a_live_phone_node() {
        let body =
            r#"{"display_phone_number":"+49 151 12345678","verified_name":"NEOTH Bot","id":"123"}"#;
        let r = parse_validate_response(true, body).unwrap();
        assert!(r.ok);
        assert_eq!(r.display_phone_number.as_deref(), Some("+49 151 12345678"));
        assert_eq!(r.verified_name.as_deref(), Some("NEOTH Bot"));
        assert!(r.error.is_none());
    }

    #[test]
    fn parse_validate_response_surfaces_bad_token() {
        let body = r#"{"error":{"message":"Invalid OAuth access token.","type":"OAuthException","code":190}}"#;
        let r = parse_validate_response(false, body).unwrap();
        assert!(!r.ok);
        let err = r.error.unwrap();
        assert!(err.contains("OAuthException") && err.contains("Invalid OAuth"));
    }

    #[test]
    fn parse_validate_response_rejects_empty_node_as_not_ok() {
        // A 200 with no phone fields (e.g. a permissions-scoped token that can
        // see the node id but not its fields) is NOT proof the channel works.
        let r = parse_validate_response(true, r#"{"id":"123"}"#).unwrap();
        assert!(!r.ok);
    }

    #[test]
    fn parse_send_response_truncates_long_bodies_to_200_chars() {
        let huge = "x".repeat(500);
        let r = parse_send_response(false, &huge).unwrap();
        let err = r.error.unwrap();
        // The error string carries a prefix + at most 200 chars of body.
        // 200 + a fixed-length prefix is well under 500.
        assert!(
            err.len() < 300,
            "expected truncation, got {} chars",
            err.len()
        );
    }

    #[test]
    fn send_message_result_serializes_to_expected_shape() {
        let r = SendMessageResult {
            ok: true,
            wa_id: Some("4915112345678".into()),
            message_id: Some("wamid.x".into()),
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"message_id\":\"wamid.x\""));
    }

    #[tokio::test]
    async fn send_text_message_rejects_empty_phone_id() {
        let token = SecretString::from("dummy");
        let r = send_text_message(&token, "", "+15551234567", "hi").await;
        let err = r.unwrap_err();
        assert!(err.to_string().contains("whatsapp_phone_id is empty"));
    }

    #[tokio::test]
    async fn send_text_message_at_posts_once_and_parses_wamid() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/123/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"contacts":[{"wa_id":"4915112345678"}],"messages":[{"id":"wamid.X"}]}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let token = SecretString::from("fake");
        let r = send_text_message_at(&server.uri(), &token, "123", "+4915112345678", "hi")
            .await
            .unwrap();
        assert!(r.ok);
        assert_eq!(r.message_id.as_deref(), Some("wamid.X"));
        // The mock's `.expect(1)` is verified on `server` drop: exactly one POST.
    }

    #[tokio::test]
    async fn validate_token_at_gets_the_phone_node() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"display_phone_number":"+49 151 1","verified_name":"NEOTH","id":"123"}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let token = SecretString::from("fake");
        let r = validate_token_at(&server.uri(), &token, "123")
            .await
            .unwrap();
        assert!(r.ok);
        assert_eq!(r.verified_name.as_deref(), Some("NEOTH"));
    }
}
