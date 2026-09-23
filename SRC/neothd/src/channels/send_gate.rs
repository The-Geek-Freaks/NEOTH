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

use crate::channels::ChannelKind;
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

/// GOLD-LF-P1-01a. Record a durable intent BEFORE the message leaves the
/// machine, returning the id its result must be paired to.
///
/// `CHANNEL_SEND` is appended only after `send_text` returns, and the rollback
/// snapshot on that path is explicitly best-effort — so until now a message
/// could reach a third party with nothing in the WAL to show for it. Egress is
/// irreversible in a way a file write is not: you cannot un-send.
///
/// Returns `None` when the frame did not reach the WAL. Callers MUST NOT send
/// in that case; `webhook_listener` already gates channel sends on
/// `WalWriterHandle::is_alive()` for exactly this reason, so failing closed
/// here continues an existing house rule rather than inventing one.
pub async fn emit_egress_intent(
    writer: &crate::wal::writer::WalWriterHandle,
    channel: &str,
    recipient: &str,
    message: &str,
    ts_unix: u64,
) -> Option<String> {
    emit_egress_intent_inner(writer, channel, recipient, message, ts_unix, None).await
}

/// Account-bound variant for the admitted nonlegacy Telegram map live path.
/// Other channel paths deliberately keep using the unbound wrapper, whose JSON
/// payload remains byte-compatible because it has no channel_ref key.
pub(crate) async fn emit_account_bound_egress_intent(
    writer: &crate::wal::writer::WalWriterHandle,
    channel: &str,
    recipient: &str,
    message: &str,
    ts_unix: u64,
    provenance: &crate::cli::serve_tasks::MappedTelegramLiveEgressProvenance,
) -> Option<String> {
    if provenance.channel_ref().channel_id != ChannelKind::Telegram
        || channel != ChannelKind::Telegram.as_str()
        || provenance.account_binding().channel_ref() != provenance.channel_ref()
    {
        tracing::warn!(
            channel,
            bound_channel = %provenance.channel_ref().channel_id.as_str(),
            "refusing account-bound egress intent with mismatched channel reference"
        );
        return None;
    }
    let intent_id = crate::wal::events::next_intent_id(
        b"channel-egress",
        &format!("{channel}:{recipient}"),
        ts_unix as i64,
    );
    let mut value = serde_json::json!({
        "intent_id": intent_id,
        "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "message_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(message.as_bytes())),
        "message_bytes": message.len(),
        "ts_unix": ts_unix,
    });
    value["channel_ref"] = serde_json::to_value(provenance.channel_ref()).ok()?;
    value["account_binding"] = serde_json::to_value(provenance.account_binding()).ok()?;
    let payload = serde_json::to_vec(&value).unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8)
        .build();
    match writer.append_authenticated(header, payload).await {
        Ok(_) => Some(intent_id),
        Err(error) => {
            tracing::warn!(
                error = %error,
                channel,
                "mandatory authenticated account-bound egress intent could not be recorded; send refused"
            );
            None
        }
    }
}

/// Authenticated legacy singleton Intent. This is intentionally a distinct
/// closed wire family from unmarked mapped Telegram records.
pub(crate) async fn emit_legacy_live_egress_intent(
    writer: &crate::wal::writer::WalWriterHandle,
    channel: &str,
    recipient: &str,
    message: &str,
    ts_unix: u64,
    provenance: &crate::cli::serve_tasks::LegacyLiveEgressProvenance,
) -> Option<String> {
    let channel_ref = provenance.channel_ref();
    if !matches!(
        channel_ref.channel_id,
        ChannelKind::Telegram | ChannelKind::Slack | ChannelKind::Discord | ChannelKind::Signal
    ) || channel_ref
        != &crate::channels::registry::ChannelRef::default_account(channel_ref.channel_id)
        || channel != channel_ref.channel_id.as_str()
    {
        return None;
    }
    let intent_id = crate::wal::events::next_intent_id(
        b"channel-egress",
        &format!("{channel}:{recipient}"),
        ts_unix as i64,
    );
    let mut value = serde_json::json!({
        "intent_id": intent_id, "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "message_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(message.as_bytes())),
        "message_bytes": message.len(), "ts_unix": ts_unix,
        "live_provenance": "legacy_singleton_v2",
    });
    value["channel_ref"] = serde_json::to_value(channel_ref).ok()?;
    let payload = serde_json::to_vec(&value).ok()?;
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8)
        .build();
    writer
        .append_authenticated(header, payload)
        .await
        .ok()
        .map(|_| intent_id)
}

async fn emit_egress_intent_inner(
    writer: &crate::wal::writer::WalWriterHandle,
    channel: &str,
    recipient: &str,
    message: &str,
    ts_unix: u64,
    channel_ref: Option<&crate::channels::registry::ChannelRef>,
) -> Option<String> {
    let intent_id = crate::wal::events::next_intent_id(
        b"channel-egress",
        &format!("{channel}:{recipient}"),
        ts_unix as i64,
    );
    // Keep the former JSON object serializer, including its map-key ordering.
    // Unbound callers never gain a channel_ref key.
    let mut value = serde_json::json!({
        "intent_id": intent_id,
        "channel": channel,
        "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(recipient.as_bytes())),
        "message_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(message.as_bytes())),
        "message_bytes": message.len(),
        "ts_unix": ts_unix,
    });
    if let Some(channel_ref) = channel_ref {
        value["channel_ref"] = serde_json::to_value(channel_ref).ok()?;
    }
    let payload = serde_json::to_vec(&value).unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8)
        .build();
    match writer.append(header, payload).await {
        Ok(_) => Some(intent_id),
        Err(error) => {
            tracing::warn!(
                error = %error,
                channel,
                "mandatory pre-egress audit intent could not be recorded; send refused"
            );
            None
        }
    }
}

/// GOLD-LF-P1-01a. Terminal outcome for one [`emit_egress_intent`]. An intent
/// with no result is a send whose fate the operator cannot determine — which
/// is the point: that state is now visible instead of absent.
pub async fn emit_egress_result(
    writer: &crate::wal::writer::WalWriterHandle,
    intent_id: &str,
    outcome: &str,
    provider_message_id: Option<&str>,
    ts_unix: u64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "provider_message_id": provider_message_id,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8)
        .build();
    if let Err(error) = writer.append(header, payload).await {
        tracing::warn!(error = %error, "WAL append CHANNEL_EGRESS_RESULT failed after egress");
    }
}

/// Terminal 0x21 record for the sealed mapped-Telegram live path. Its payload
/// is deliberately identical to the unbound result; the authenticated marker
/// binds it to the earlier authenticated mapped intent without copying account
/// data into the result frame.
pub(crate) async fn emit_account_bound_egress_result(
    writer: &crate::wal::writer::WalWriterHandle,
    intent_id: &str,
    outcome: &str,
    provider_message_id: Option<&str>,
    ts_unix: u64,
    provenance: &crate::cli::serve_tasks::MappedTelegramLiveEgressProvenance,
) -> std::result::Result<(), ()> {
    if provenance.channel_ref().channel_id != ChannelKind::Telegram {
        tracing::warn!("refusing account-bound egress result with non-Telegram provenance");
        return Err(());
    }
    if provenance.account_binding().channel_ref() != provenance.channel_ref() {
        tracing::warn!("refusing account-bound egress result with mismatched sealed binding");
        return Err(());
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "provider_message_id": provider_message_id,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8)
        .build();
    writer
        .append_authenticated(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                "authenticated WAL append CHANNEL_EGRESS_RESULT failed after bound egress"
            );
        })
}

pub(crate) async fn emit_legacy_live_egress_result(
    writer: &crate::wal::writer::WalWriterHandle,
    intent_id: &str,
    outcome: &str,
    provider_message_id: Option<&str>,
    ts_unix: u64,
    provenance: &crate::cli::serve_tasks::LegacyLiveEgressProvenance,
) -> std::result::Result<(), ()> {
    let channel_ref = provenance.channel_ref();
    if !matches!(
        channel_ref.channel_id,
        ChannelKind::Telegram | ChannelKind::Slack | ChannelKind::Discord | ChannelKind::Signal
    ) || channel_ref
        != &crate::channels::registry::ChannelRef::default_account(channel_ref.channel_id)
    {
        return Err(());
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id, "outcome": outcome,
        "provider_message_id": provider_message_id, "ts_unix": ts_unix,
    }))
    .map_err(|_| ())?;
    let header = crate::wal::HeaderBuilder::new(0x00, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8)
        .build();
    writer
        .append_authenticated(header, payload)
        .await
        .map(|_| ())
        .map_err(|_| ())
}

#[cfg(test)]
mod intent_tests {
    use super::*;
    use crate::wal::events::ExtendedSubtype;
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;

    fn mapped_bundle_from_runtime(
        account_id: &str,
        allowed_user_id: u64,
    ) -> crate::cli::serve_tasks::TelegramAccountBundle {
        let account_id = crate::channels::registry::ChannelAccountId::new(account_id)
            .expect("valid mapped fixture account id");
        let mut runtime = crate::config::RuntimeConfigPair {
            config: crate::config::FreedomConfig::default(),
            raw_credentials: crate::config::credentials::Credentials::default(),
            credentials: crate::config::credentials::Credentials::default(),
        };
        runtime.config.channel_accounts.telegram.insert(
            account_id.clone(),
            crate::config::TelegramAccountConfig {
                allowed_user_id,
                ..Default::default()
            },
        );
        let credential = crate::config::credentials::TelegramAccountCredentials {
            token: Some(crate::secret::SecretString::new(
                "mapped-fixture-token".to_owned(),
            )),
        };
        runtime
            .raw_credentials
            .channel_accounts
            .telegram
            .insert(account_id.clone(), credential.clone());
        runtime
            .credentials
            .channel_accounts
            .telegram
            .insert(account_id.clone(), credential);
        crate::cli::serve_tasks::telegram_account_bundles(&runtime)
            .expect("coherent mapped runtime pair yields one fixture bundle")
            .into_iter()
            .next()
            .expect("one exact mapped fixture bundle")
    }

    #[tokio::test]
    async fn egress_intent_binds_the_message_by_hash_and_pairs_its_result() {
        let (writer, join, _home, seg) =
            crate::wal::writer::spawn_isolated_ready_test_writer("send-gate-intent")
                .await
                .expect("start ready, isolated send-gate WAL fixture");

        let id = emit_egress_intent(&writer, "telegram", "chat-42", "hallo", 1_700_000_000)
            .await
            .expect("intent must be recorded on a live writer");
        emit_egress_result(&writer, &id, "delivered", Some("msg-7"), 1_700_000_000).await;
        drop(writer);
        join.await
            .expect("send-gate writer task must join")
            .expect("send-gate writer must complete successfully");

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut frames = Vec::new();
        let mut raw_unbound_intent = None;
        let mut cursor = SEGMENT_HEADER_LEN;
        while cursor < bytes.len() {
            let Ok(frame) = decode_frame(&bytes[cursor..]) else {
                break;
            };
            if frame.header.event_subtype == ExtendedSubtype::ChannelEgressIntent as u8 {
                raw_unbound_intent = Some(frame.payload.to_vec());
            }
            frames.push((
                frame.header.event_subtype,
                serde_json::from_slice::<serde_json::Value>(frame.payload)
                    .unwrap_or(serde_json::Value::Null),
            ));
            cursor += frame.header.total_len as usize;
        }

        let intent = frames
            .iter()
            .find(|(s, _)| *s == ExtendedSubtype::ChannelEgressIntent as u8)
            .expect("intent frame");
        let result = frames
            .iter()
            .find(|(s, _)| *s == ExtendedSubtype::ChannelEgressResult as u8)
            .expect("result frame");

        assert_eq!(intent.1["intent_id"], result.1["intent_id"]);
        assert_eq!(result.1["outcome"], "delivered");
        // Neither the recipient nor the body may appear in the clear.
        let intent_text = intent.1.to_string();
        assert!(!intent_text.contains("chat-42"), "recipient must be hashed");
        assert!(!intent_text.contains("hallo"), "body must be hashed");
        assert!(
            intent.1.get("channel_ref").is_none(),
            "unbound compatibility payload must not gain an account reference"
        );
        let expected_legacy_intent = serde_json::to_vec(&serde_json::json!({
            "intent_id": intent.1["intent_id"].as_str().unwrap(),
            "channel": "telegram",
            "to_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64("chat-42".as_bytes())),
            "message_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64("hallo".as_bytes())),
            "message_bytes": 5,
            "ts_unix": 1_700_000_000_u64,
        }))
        .unwrap();
        assert_eq!(
            raw_unbound_intent.expect("raw unbound intent"),
            expected_legacy_intent,
            "the None branch retains the exact former intent JSON bytes"
        );
        assert_eq!(intent.1["message_bytes"], 5);
    }

    #[tokio::test]
    async fn mapped_telegram_intent_carries_only_typed_ref_and_mismatch_writes_nothing() {
        let home = tempfile::tempdir().expect("create authenticated bound send-gate home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create authenticated bound send-gate WAL");
        let seg = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(seg.clone(), home.path().to_path_buf())
                .expect("spawn authenticated bound send-gate WAL fixture");
        ready
            .wait()
            .await
            .expect("initialize authenticated bound send-gate WAL fixture");
        let bundle_a = mapped_bundle_from_runtime("account_a", 101);
        let bundle_default = mapped_bundle_from_runtime("default", 202);
        let provenance_a = bundle_a.mapped_live_egress_provenance().unwrap();
        let provenance_default = bundle_default.mapped_live_egress_provenance().unwrap();
        let id_a = emit_account_bound_egress_intent(
            &writer,
            "telegram",
            "private-recipient-a",
            "private-body-a",
            1_700_000_000,
            &provenance_a,
        )
        .await
        .expect("mapped account A intent");
        let id_default = emit_account_bound_egress_intent(
            &writer,
            "telegram",
            "private-recipient-default",
            "private-body-default",
            1_700_000_001,
            &provenance_default,
        )
        .await
        .expect("literal mapped default intent");
        assert!(
            emit_account_bound_egress_intent(
                &writer,
                "slack",
                "must-not-reach-wal",
                "must-not-reach-wal",
                1_700_000_002,
                &provenance_a,
            )
            .await
            .is_none(),
            "mismatched ref refuses before an egress intent is appended"
        );
        drop(writer);
        join.await.unwrap().unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        let mut refs = Vec::new();
        while cursor < bytes.len() {
            let frame = decode_frame(&bytes[cursor..]).expect("complete test frame");
            if frame.header.event_subtype == ExtendedSubtype::ChannelEgressIntent as u8 {
                let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                refs.push((payload["intent_id"].clone(), payload));
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(refs.len(), 2, "mismatch added no WAL intent");
        for (intent_id, payload) in refs {
            assert!(
                intent_id.as_str().is_some_and(|id| id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
                "bound live ids stay canonical lower-case 32-hex"
            );
            let text = payload.to_string();
            assert!(!text.contains("private-recipient"));
            assert!(!text.contains("private-body"));
            assert!(!text.contains("token"));
            assert_eq!(payload["channel"], "telegram");
            assert!(
                payload["channel_ref"].is_object()
                    && payload["account_binding"]["channel_ref"] == payload["channel_ref"],
                "the runtime-minted provenance keeps its sealed binding on the exact typed ref"
            );
        }
        assert_eq!(id_a.len(), 32);
        assert_eq!(id_default.len(), 32);
    }

    #[tokio::test]
    async fn sealed_default_discord_intent_and_result_are_authenticated_and_bound() {
        let home = tempfile::tempdir().expect("create Discord live-evidence home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create Discord live-evidence WAL");
        let segment = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.path().to_path_buf())
                .expect("spawn Discord live-evidence WAL writer");
        ready
            .wait()
            .await
            .expect("initialize Discord live-evidence WAL writer");
        let provenance =
            crate::cli::serve_tasks::legacy_live_egress_provenance_for_test(ChannelKind::Discord)
                .expect("Discord belongs to the closed default live-evidence family");
        let intent_id = emit_legacy_live_egress_intent(
            &writer,
            "discord",
            "private-discord-channel",
            "private-discord-reply",
            1_700_000_000,
            &provenance,
        )
        .await
        .expect("sealed Discord intent");
        emit_legacy_live_egress_result(
            &writer,
            &intent_id,
            "delivered",
            Some("discord-message-id"),
            1_700_000_001,
            &provenance,
        )
        .await
        .expect("sealed Discord terminal result");
        drop(writer);
        join.await
            .expect("join Discord live-evidence WAL writer")
            .expect("close Discord live-evidence WAL writer");

        let bytes = tokio::fs::read(segment).await.expect("read Discord WAL");
        let mut cursor = SEGMENT_HEADER_LEN;
        let mut frames = Vec::new();
        while cursor < bytes.len() {
            let frame = decode_frame(&bytes[cursor..]).expect("complete Discord evidence frame");
            if frame.header.event_subtype == ExtendedSubtype::ChannelEgressIntent as u8
                || frame.header.event_subtype == ExtendedSubtype::ChannelEgressResult as u8
            {
                frames.push((
                    frame.header.event_subtype,
                    serde_json::from_slice::<serde_json::Value>(frame.payload)
                        .expect("Discord evidence JSON"),
                ));
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, ExtendedSubtype::ChannelEgressIntent as u8);
        assert_eq!(frames[0].1["channel"], "discord");
        assert_eq!(frames[0].1["channel_ref"]["channel_id"], "discord");
        assert_eq!(frames[0].1["channel_ref"]["account_id"], "default");
        assert_eq!(frames[0].1["live_provenance"], "legacy_singleton_v2");
        assert_eq!(frames[1].0, ExtendedSubtype::ChannelEgressResult as u8);
        assert_eq!(frames[1].1["intent_id"], frames[0].1["intent_id"]);
        assert_eq!(frames[1].1["outcome"], "delivered");
    }

    #[tokio::test]
    async fn a_dead_writer_yields_no_intent_so_the_caller_must_refuse_the_send() {
        // The callers turn this `None` into a refusal. Proving it here keeps
        // the contract testable without standing up a live channel.
        let writer = crate::wal::writer::closed_test_writer();

        let id = emit_egress_intent(&writer, "telegram", "chat-42", "hallo", 1_700_000_000).await;
        assert!(
            id.is_none(),
            "an unrecordable intent must not yield an id to send under"
        );
    }

    #[tokio::test]
    async fn mapped_terminal_receipt_is_an_error_when_authenticated_markers_are_unavailable() {
        let home = tempfile::tempdir().expect("create marker-disabled mapped-result home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create marker-disabled mapped-result WAL");
        let segment = wal.join(format!(
            "{}-{}-000001.wal",
            uuid::Uuid::now_v7(),
            crate::wal::writer::HMAC_ROTATION_SURFACE,
        ));
        let (writer, join) =
            crate::wal::writer::spawn_hmac_rotation_for_home(segment, home.path().to_path_buf())
                .expect("start live marker-disabled writer");
        let bundle = mapped_bundle_from_runtime("account_a", 101);
        assert!(
            emit_account_bound_egress_result(
                &writer,
                "0123456789abcdef0123456789abcdef",
                "delivered",
                Some("provider-id"),
                crate::time::now_unix_secs(),
                &bundle.mapped_live_egress_provenance().unwrap(),
            )
            .await
            .is_err(),
            "a mapped terminal without its authenticated receipt must be visible to the caller"
        );
        drop(writer);
        join.await.expect("marker-disabled writer task joins");
    }
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
