//! WhatsApp Business Cloud API send surface — feeds the `whatsapp`
//! scaffold's `send_text` implementation so operators can post one-shot
//! messages today even though the inbound webhook is Phase 2.
//!
//! Operator setup:
//!   1. Configure `whatsapp_token` (long-lived system-user access
//!      token) + `whatsapp_phone_id` (the numeric phone-number id
//!      from the Meta console) via `neoth init` or `credentials.yaml`.
//!   2. Run `neoth whatsapp send --to <e164> --message "..."` —
//!      calls `https://graph.facebook.com/v18.0/<phone_id>/messages`
//!      with the configured token.
//!
//! Receive path (webhook): deferred to Phase 2 — needs a public HTTPS
//! endpoint operator-side and Meta's `hub.verify_token` round-trip.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

/// Result of a `messages` POST. `id` is WhatsApp's wamid (e.g.
/// `"wamid.HBgL..."`); operators can use it for delivery-status webhooks
/// once the receive path lands.
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
    if phone_number_id.is_empty() {
        anyhow::bail!("whatsapp_phone_id is empty — set it in credentials.yaml");
    }
    let url = format!("https://graph.facebook.com/v18.0/{phone_number_id}/messages");
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
    let body_text = resp.text().await.unwrap_or_default();
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
}
