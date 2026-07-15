//! P0 — channel-send governance gate.
//!
//! Outbound channel sends (today: the WhatsApp webhook reply path in
//! [`super::webhook_listener`]) are real external mutations that left no
//! governance trail. Every send now passes through ONE decision point:
//!
//!   1. Evaluate the operator's channel-send permission ([`Action::ChannelSend`]
//!      under the active autonomy level). An explicit **Deny** blocks the send
//!      and emits `0x68 CHANNEL_SEND_DENIED`.
//!   2. **required-audit fail-closed**: when the operator demands every send be
//!      provable, a send that cannot be audited is REFUSED (never silently
//!      sent).
//!   3. **dry-run**: skip the real API call but still emit the audit so the
//!      operator sees what WOULD have gone out.
//!   4. Otherwise send + emit `0x67 CHANNEL_SEND`.
//!
//! The audit is **metadata-only**: the recipient (a phone number for WhatsApp)
//! and the message body are xxh3-64 HASHED, never stored in the clear.

use crate::permissions::Decision;

/// What the send path should do — decided PURELY from the inputs so the policy
/// is unit-testable without a network or a WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelSendVerdict {
    /// Proceed with the real API send, then emit `CHANNEL_SEND`.
    Send,
    /// `dry_run`: do NOT hit the API, but emit a dry-run `CHANNEL_SEND` so the
    /// operator sees what would have gone out.
    DryRun,
    /// The permission gate denied the send — emit `CHANNEL_SEND_DENIED`, do not
    /// send. Carries the gate's reason.
    Denied(String),
    /// `required_audit` is on but the audit sink is unavailable — fail closed:
    /// do not send, do not silently proceed.
    RefusedNoAudit,
}

/// PURE send decision. Order is load-bearing:
///   1. A **Deny** always wins — a denied message is never sent, not even in
///      dry-run (dry-run is a preview of an *allowed* send).
///   2. **required-audit fail-closed** before any send.
///   3. dry-run preview.
///   4. else Send.
///
/// `Decision::Confirm` (e.g. Strict autonomy) has NO arm here and falls through
/// to `Send`. That degrade is UNREACHABLE on the standard serve.rs
/// `build_pipeline_handler` wiring: that pipeline runs a
/// `Gate::for_policy(..).with_confirm(ConfirmStrategy::FailClosed)` ChannelSend
/// gate which resolves Strict's Confirm to Deny and returns `Ok(None)` BEFORE
/// `decide_channel_send` is ever reached. The fallthrough therefore only fires
/// for an operator-constructed listener that bypasses that pipeline gate — and
/// when it does, the `confirm_degraded: true` flag in the `CHANNEL_SEND`
/// payload marks the governance posture in the WAL. The durable audit + the
/// hard Deny remain the governance for a headless, TTY-less reply path.
pub fn decide_channel_send(
    decision: &Decision,
    dry_run: bool,
    audit_writable: bool,
    required_audit: bool,
) -> ChannelSendVerdict {
    if let Decision::Deny(reason) = decision {
        return ChannelSendVerdict::Denied(reason.clone());
    }
    if required_audit && !audit_writable {
        return ChannelSendVerdict::RefusedNoAudit;
    }
    if dry_run {
        return ChannelSendVerdict::DryRun;
    }
    ChannelSendVerdict::Send
}

/// Build the metadata-only `CHANNEL_SEND` payload for an outbound send. The
/// recipient AND the message body are xxh3-64 HASHED — never the phone number
/// or the text in the clear. PURE so the no-plaintext invariant is testable.
///
/// `confirm_degraded` records whether a Strict-autonomy `Decision::Confirm` was
/// degraded to a send on this path (see [`decide_channel_send`]); `false` on
/// every standard production path (the pipeline gate blocks Confirm upstream).
pub fn channel_egress_payload(
    channel: &str,
    recipient: &str,
    message: &str,
    provider_message_id: Option<&str>,
    dry_run: bool,
    confirm_degraded: bool,
    ts_unix: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "message_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(message.as_bytes())),
        "message_bytes": message.len(),
        "provider_message_id": provider_message_id,
        "dry_run": dry_run,
        "confirm_degraded": confirm_degraded,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// Build the `CHANNEL_SEND_DENIED` payload for a refused send. Also metadata-only
/// (hashed recipient, no body) + the gate's reason.
pub fn channel_send_denied_payload(
    channel: &str,
    recipient: &str,
    reason: &str,
    ts_unix: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "action": "channel_send",
        "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// Build a `CHANNEL_SEND` payload for a send that was ATTEMPTED but did NOT
/// reach the recipient (Meta API rejection or transport failure). Same
/// metadata-only shape — hashed recipient, no body — plus `delivered: false`
/// and a coarse `error_kind`. Without this, a rejected/failed send leaves no
/// WAL trace at all, making it indistinguishable from a reply that never
/// reached the Send verdict. PURE.
pub fn channel_egress_failed_payload(
    channel: &str,
    recipient: &str,
    error_kind: &str,
    ts_unix: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "delivered": false,
        "error_kind": error_kind,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_always_wins_even_over_dry_run() {
        let v = decide_channel_send(&Decision::Deny("blocked".into()), true, true, true);
        assert_eq!(v, ChannelSendVerdict::Denied("blocked".into()));
    }

    #[test]
    fn required_audit_fails_closed_when_unwritable() {
        // Allowed, but audit can't be written + required → refuse (don't send).
        assert_eq!(
            decide_channel_send(&Decision::Allow, false, false, true),
            ChannelSendVerdict::RefusedNoAudit
        );
        // required but writable → proceeds.
        assert_eq!(
            decide_channel_send(&Decision::Allow, false, true, true),
            ChannelSendVerdict::Send
        );
        // not required + unwritable → still sends (best-effort posture).
        assert_eq!(
            decide_channel_send(&Decision::Allow, false, false, false),
            ChannelSendVerdict::Send
        );
    }

    #[test]
    fn dry_run_previews_an_allowed_send() {
        assert_eq!(
            decide_channel_send(&Decision::Allow, true, true, false),
            ChannelSendVerdict::DryRun
        );
    }

    #[test]
    fn confirm_degrades_to_audited_send_on_the_reply_path() {
        assert_eq!(
            decide_channel_send(&Decision::Confirm("strict".into()), false, true, false),
            ChannelSendVerdict::Send
        );
    }

    #[test]
    fn egress_payload_is_metadata_only_no_plaintext() {
        let recipient = "+4915112345678";
        let message = "secret message body";
        let bytes = channel_egress_payload(
            "whatsapp",
            recipient,
            message,
            Some("wamid.X"),
            false,
            true,
            1700,
        );
        let s = String::from_utf8(bytes).unwrap();
        // The phone number and the body NEVER appear in the clear.
        assert!(!s.contains(recipient), "recipient phone leaked: {s}");
        assert!(
            !s.contains("secret message body"),
            "message body leaked: {s}"
        );
        // But the hashes + safe metadata DO.
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["channel"], "whatsapp");
        assert_eq!(v["message_bytes"], message.len());
        assert_eq!(v["provider_message_id"], "wamid.X");
        assert_eq!(
            v["to_hash"],
            format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes()))
        );
        assert!(v["message_hash"].as_str().unwrap().len() == 16);
        assert_eq!(v["confirm_degraded"], true);
    }

    #[test]
    fn denied_payload_hashes_recipient_and_omits_body() {
        let bytes =
            channel_send_denied_payload("whatsapp", "+4915112345678", "strict: confirm", 1700);
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains("+4915112345678"));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["action"], "channel_send");
        assert_eq!(v["reason"], "strict: confirm");
        assert!(
            v.get("message_hash").is_none(),
            "no body field at all on a denial"
        );
    }

    #[test]
    fn failed_payload_hashes_recipient_marks_undelivered_no_body() {
        let bytes =
            channel_egress_failed_payload("whatsapp", "+4915112345678", "meta_api_error", 1700);
        let s = String::from_utf8(bytes).unwrap();
        // No phone number in the clear, and no body field ever.
        assert!(!s.contains("+4915112345678"), "recipient phone leaked: {s}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["channel"], "whatsapp");
        assert_eq!(v["delivered"], false);
        assert_eq!(v["error_kind"], "meta_api_error");
        assert!(
            v.get("message_hash").is_none(),
            "no body field on a failed send"
        );
        assert_eq!(
            v["to_hash"],
            format!(
                "{:016x}",
                xxhash_rust::xxh3::xxh3_64("+4915112345678".as_bytes())
            )
        );
    }
}
