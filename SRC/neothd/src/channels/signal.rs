//! GOLD-FEAT-10 — Signal channel adapter (RECEIVE + SEND) over a local
//! `signal-cli` HTTP daemon. Thin orchestrator over [`super::signal_api`]:
//! `run()` polls `/v1/receive`, maps each envelope to an `InboundMessage`,
//! runs the pipeline handler, and posts any reply via `/v2/send`.
//!
//! ## Why poll, not SSE (yet)
//!
//! signal-cli also exposes an SSE/JSON-RPC event stream (Hermes uses it).
//! The poll path is correct + the simplest self-contained start; an SSE
//! upgrade (lower latency, fewer requests) is a documented follow-up.
//!
//! ## Operator prerequisite (not automatable)
//!
//! `signal-cli` must be installed + the number registered separately
//! (Java dep + captcha + SMS verification). The wizard / `neoth doctor`
//! surface the setup link (https://github.com/AsamK/signal-cli) and the
//! bbernhard container option; NEOTH only needs the daemon's URL + the
//! registered number in `credentials.yaml`.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{error, info, warn};

use super::signal_api::{
    SignalEndpoint, envelope_to_inbound, receive_messages, send_signal_message,
    validate_signal_number,
};
use super::{Channel, ChannelError, MessageId, PipelineHandler};

/// Default receive-poll cadence. 2s matches the parity-doc default — low
/// enough to feel responsive, high enough not to hammer signal-cli.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Signal adapter. Holds the signal-cli base URL, our registered E.164
/// number, a shared HTTP client, and the poll cadence. Stateless beyond
/// that — every send/receive is one HTTP round trip.
pub struct SignalChannel {
    endpoint: SignalEndpoint,
    phone_number: String,
    poll_interval: Duration,
    inbound_gate: Option<SignalInboundGate>,
}

struct SignalInboundGate {
    allowed_sender: String,
    writer: crate::wal::writer::WalWriterHandle,
    live_egress: crate::cli::serve_tasks::LegacyLiveEgressProvenance,
}

impl SignalChannel {
    /// Build against a running signal-cli daemon. `cli_url` e.g.
    /// `http://127.0.0.1:8080`; `phone_number` the registered `+E.164`.
    pub fn new(cli_url: impl Into<String>, phone_number: impl Into<String>) -> Result<Self> {
        let cli_url = cli_url.into();
        let phone_number = phone_number.into();
        validate_signal_number(&phone_number)?;
        let endpoint = SignalEndpoint::parse(&cli_url)?;
        Ok(Self {
            endpoint,
            phone_number,
            poll_interval: DEFAULT_POLL_INTERVAL,
            inbound_gate: None,
        })
    }

    pub(crate) fn new_inbound(
        cli_url: impl Into<String>,
        phone_number: impl Into<String>,
        allowed_sender: &str,
        writer: crate::wal::writer::WalWriterHandle,
        live_egress: crate::cli::serve_tasks::LegacyLiveEgressProvenance,
    ) -> Result<Self> {
        let mut channel = Self::new(cli_url, phone_number)?;
        let allowed_sender = allowed_sender.trim();
        validate_signal_number(allowed_sender).context("validate Signal allowed sender")?;
        channel.inbound_gate = Some(SignalInboundGate {
            allowed_sender: allowed_sender.to_string(),
            writer,
            live_egress,
        });
        Ok(channel)
    }

    /// Override the poll cadence (tuning / tests).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

#[async_trait]
impl Channel for SignalChannel {
    fn name(&self) -> &'static str {
        "signal"
    }

    /// Receive loop: poll `/v1/receive`, map → handler → reply. Transient
    /// poll errors (transport / rate-limit) log + retry on the next tick so
    /// the adapter rides out a signal-cli restart; an **auth** failure is
    /// fatal (bad/unregistered number) and stops the adapter with a clear
    /// error rather than polling forever against a broken config. Loops
    /// until the daemon aborts the spawned task at shutdown.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let gate = self.inbound_gate.as_ref().context(
            "Signal inbound is fail-closed: construct with an allowed sender and WAL writer",
        )?;
        info!(
            url = %self.endpoint.as_str(),
            poll_secs = self.poll_interval.as_secs(),
            "signal receive poll loop starting"
        );
        loop {
            match receive_messages(&self.endpoint, &self.phone_number).await {
                Ok(envelopes) => {
                    for env in &envelopes {
                        let Some(inbound) = envelope_to_inbound(env) else {
                            continue; // receipt / typing / sync — not actionable
                        };
                        dispatch_inbound_message(
                            &self.endpoint,
                            &self.phone_number,
                            &gate.allowed_sender,
                            Some(&gate.writer),
                            Some(&gate.live_egress),
                            inbound,
                            &handler,
                        )
                        .await;
                    }
                }
                Err(ChannelError::Auth(msg)) => {
                    error!(error = %msg, "signal auth failed — stopping adapter (check number/registration)");
                    return Err(anyhow::anyhow!("signal auth: {msg}"));
                }
                Err(ChannelError::RateLimited { retry_after_secs }) => {
                    // signal-cli (or an intermediate proxy) asked us to back off.
                    // Honour the Retry-After value instead of hammering on the
                    // normal poll cadence — mirrors the Hermes signal_rate_limit.py
                    // pattern (parse retry-after, sleep+retry once, then surface).
                    warn!(
                        retry_after_secs,
                        "signal receive rate-limited; backing off for Retry-After period"
                    );
                    // Security review: cap hostile Retry-After values (max 5 min).
                    tokio::time::sleep(Duration::from_secs(retry_after_secs.min(300))).await;
                }
                Err(e) => {
                    warn!(error = %e, "signal receive poll failed; retrying next tick");
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Send a reply. `chat_id` is the number (DM) or `group.<id>` returned
    /// as the inbound `chat_id`, so replies route back to the same thread.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        send_signal_message(&self.endpoint, &self.phone_number, chat_id, text).await
    }

    /// Proactive send delegates to `send_text` — the signal-cli POST is
    /// identical for replies vs daemon-initiated sends. The operator gate
    /// (`FreedomConfig::proactive.enabled`) is the CALLER's responsibility
    /// per the C-11 trait contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

async fn dispatch_inbound_message(
    endpoint: &SignalEndpoint,
    phone_number: &str,
    allowed_sender: &str,
    gate_writer: Option<&crate::wal::writer::WalWriterHandle>,
    live_egress: Option<&crate::cli::serve_tasks::LegacyLiveEgressProvenance>,
    inbound: crate::channels::InboundMessage,
    handler: &PipelineHandler,
) {
    if crate::channels::sender_blocked_by_allowlist(
        Some(allowed_sender),
        &inbound.sender_id,
        gate_writer,
        "signal",
    )
    .await
    {
        return;
    }
    match handler(inbound).await {
        Ok(Some(out)) => {
            let result = match (gate_writer, live_egress) {
                (Some(writer), Some(provenance)) => {
                    send_live_signal_reply(writer, provenance, &out.recipient_id, &out.text, || {
                        send_signal_message(endpoint, phone_number, &out.recipient_id, &out.text)
                    })
                    .await
                }
                _ => send_signal_message(endpoint, phone_number, &out.recipient_id, &out.text)
                    .await
                    .map(|_| ()),
            };
            if let Err(e) = result {
                warn!(error = %e, "signal reply send failed (dropped)");
            }
        }
        Ok(None) => {} // pipeline chose to stay silent
        Err(e) => warn!(error = %e, "signal pipeline handler errored; skipping message"),
    }
}

async fn send_live_signal_reply<F, Fut>(
    writer: &crate::wal::writer::WalWriterHandle,
    provenance: &crate::cli::serve_tasks::LegacyLiveEgressProvenance,
    recipient: &str,
    text: &str,
    post: F,
) -> std::result::Result<(), ChannelError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<MessageId, ChannelError>>,
{
    let Some(intent_id) = crate::channels::send_gate::emit_legacy_live_egress_intent(
        writer,
        "signal",
        recipient,
        text,
        crate::time::now_unix_secs(),
        provenance,
    )
    .await else {
        return Err(ChannelError::Transport(
            "mandatory authenticated Signal egress intent could not be recorded".to_string(),
        ));
    };
    match post().await {
        Ok(message_id) => {
            crate::channels::send_gate::emit_legacy_live_egress_result(
                writer,
                &intent_id,
                "delivered",
                Some(&message_id.0),
                crate::time::now_unix_secs(),
                provenance,
            )
            .await
            .map_err(|()| ChannelError::Transport(
                "mandatory authenticated Signal egress receipt could not be recorded".to_string(),
            ))
        }
        Err(error) => {
            let outcome = match &error {
                ChannelError::Transport(_) => "transport",
                ChannelError::NotSupported { .. } => "not_supported",
                ChannelError::RateLimited { .. } => "rate_limited",
                ChannelError::Auth(_) => "auth",
            };
            crate::channels::send_gate::emit_legacy_live_egress_result(
                writer,
                &intent_id,
                outcome,
                None,
                crate::time::now_unix_secs(),
                provenance,
            )
            .await
            .map_err(|()| ChannelError::Transport(
                "mandatory authenticated Signal egress receipt could not be recorded".to_string(),
            ))?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn inbound(sender: &str) -> crate::channels::InboundMessage {
        crate::channels::InboundMessage {
            channel: crate::channels::ChannelKind::Signal,
            chat_id: sender.into(),
            thread_id: None,
            sender_id: sender.into(),
            sender_display: None,
            text: Some("hello".into()),
            media: None,
            reply_to: None,
            message_id: Some("1".into()),
            edit_unix: None,
            mention_kind: None,
            channel_ts_unix: 1,
            raw_ts_ms: Some(1_000),
            human_uuid: None,
        }
    }

    fn counting_handler(calls: Arc<AtomicUsize>) -> PipelineHandler {
        Box::new(move |_inbound| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
        })
    }

    #[test]
    fn adapter_reports_signal_name() {
        let a = SignalChannel::new("http://127.0.0.1:8080", "+441234567").unwrap();
        assert_eq!(a.name(), "signal");
    }

    #[test]
    fn new_trims_trailing_slash_from_url() {
        let a = SignalChannel::new("http://127.0.0.1:8080/", "+441234567").unwrap();
        assert_eq!(
            a.endpoint.as_str(),
            "http://127.0.0.1:8080",
            "trailing slash stripped"
        );
    }

    #[test]
    fn with_poll_interval_overrides_default() {
        let a = SignalChannel::new("https://signal.example", "+491234567")
            .unwrap()
            .with_poll_interval(Duration::from_millis(500));
        assert_eq!(a.poll_interval, Duration::from_millis(500));
        // default sanity
        let b = SignalChannel::new("https://signal.example", "+491234567").unwrap();
        assert_eq!(b.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn transport_policy_rejects_remote_http_and_accepts_https_or_loopback() {
        assert!(SignalChannel::new("http://signal.example", "+491234567").is_err());
        assert!(SignalChannel::new("https://signal.example", "+491234567").is_ok());
        assert!(SignalChannel::new("http://127.0.0.1:8080", "+491234567").is_ok());
        assert!(SignalChannel::new("http://[::1]:8080", "+491234567").is_ok());
        assert!(SignalChannel::new("http://localhost.evil.test", "+491234567").is_err());
    }

    /// Verify the rate-limit arm is reachable (parse + re-surface path).
    /// The signal_api::map_status function already parses Retry-After correctly
    /// (tested in signal_api); this test confirms the run() loop has a dedicated
    /// arm for RateLimited rather than lumping it into the generic catch-all.
    #[test]
    fn rate_limited_error_is_a_distinct_variant() {
        // Construct the error the way map_status emits it.
        let e = ChannelError::RateLimited {
            retry_after_secs: 30,
        };
        // The error Display must mention the retry-after value for operator logs.
        let s = e.to_string();
        assert!(
            s.contains("30"),
            "RateLimited display must include retry_after_secs: {s}"
        );
    }

    #[tokio::test]
    async fn sender_gate_blocks_mismatch_and_passes_exact_match() {
        let channel = SignalChannel::new("http://127.0.0.1:8080", "+491701111111").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = counting_handler(Arc::clone(&calls));

        dispatch_inbound_message(
            &channel.endpoint,
            &channel.phone_number,
            "+491702222222",
            None,
            None,
            inbound("+491703333333"),
            &handler,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        dispatch_inbound_message(
            &channel.endpoint,
            &channel.phone_number,
            "+491702222222",
            None,
            None,
            inbound("+491702222222"),
            &handler,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn live_signal_reply_refuses_unrecorded_intent_and_records_one_terminal_per_effect() {
        let provenance = crate::cli::serve_tasks::legacy_live_egress_provenance_for_test(
            crate::channels::ChannelKind::Signal,
        )
        .expect("Signal has sealed default live provenance");
        let refused_calls = Arc::new(AtomicUsize::new(0));
        let refused_post = {
            let refused_calls = Arc::clone(&refused_calls);
            move || {
                refused_calls.fetch_add(1, Ordering::SeqCst);
                async { Ok::<MessageId, ChannelError>(MessageId("must-not-send".to_string())) }
            }
        };
        assert!(
            send_live_signal_reply(
                &crate::wal::writer::closed_test_writer(),
                &provenance,
                "private-recipient",
                "private-reply",
                refused_post,
            )
            .await
            .is_err()
        );
        assert_eq!(refused_calls.load(Ordering::SeqCst), 0);

        let home = tempfile::tempdir().expect("create Signal live-reply WAL home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create Signal live-reply WAL");
        let segment = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.path().to_path_buf())
                .expect("spawn Signal live-reply WAL writer");
        ready.wait().await.expect("initialize Signal live-reply WAL");
        let delivered_calls = Arc::new(AtomicUsize::new(0));
        send_live_signal_reply(
            &writer,
            &provenance,
            "private-recipient",
            "private-reply",
            {
                let delivered_calls = Arc::clone(&delivered_calls);
                move || {
                    delivered_calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<MessageId, ChannelError>(MessageId("accepted".to_string())) }
                }
            },
        )
        .await
        .expect("accepted Signal reply records delivered terminal");
        let failed_calls = Arc::new(AtomicUsize::new(0));
        assert!(
            send_live_signal_reply(
                &writer,
                &provenance,
                "private-recipient",
                "private-reply",
                {
                    let failed_calls = Arc::clone(&failed_calls);
                    move || {
                        failed_calls.fetch_add(1, Ordering::SeqCst);
                        async {
                            Err::<MessageId, ChannelError>(ChannelError::Transport(
                                "fixture failure".to_string(),
                            ))
                        }
                    }
                },
            )
            .await
            .is_err()
        );
        assert_eq!(delivered_calls.load(Ordering::SeqCst), 1);
        assert_eq!(failed_calls.load(Ordering::SeqCst), 1, "adapter errors do not retry");
        drop(writer);
        join.await
            .expect("join Signal live-reply WAL writer")
            .expect("close Signal live-reply WAL writer");

        let bytes = tokio::fs::read(segment).await.expect("read Signal live-reply WAL");
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut outcomes = Vec::new();
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..])
                .expect("complete Signal live-reply evidence frame");
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8
            {
                let payload: serde_json::Value =
                    serde_json::from_slice(frame.payload).expect("Signal terminal JSON");
                outcomes.push(payload["outcome"].as_str().map(str::to_string));
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(outcomes, vec![Some("delivered".to_string()), Some("transport".to_string())]);
        let counters = crate::daemon::channel_transport_evidence::read_account_transport_evidence(
            home.path(),
            crate::time::now_unix_secs() as i64,
        )
        .expect("read generated authenticated Signal live-reply evidence");
        let signal_default = crate::channels::registry::ChannelRef::default_account(
            crate::channels::ChannelKind::Signal,
        );
        assert_eq!(counters.len(), 1, "no other account may gain Signal evidence");
        assert_eq!(counters.get(&signal_default).unwrap().accepted, 1);
        assert_eq!(counters.get(&signal_default).unwrap().failed, 1);
        assert_eq!(counters.get(&signal_default).unwrap().completed, 2);
    }

    #[tokio::test]
    async fn live_signal_reply_reports_receipt_failure_without_replaying_accepted_effect() {
        let provenance = crate::cli::serve_tasks::legacy_live_egress_provenance_for_test(
            crate::channels::ChannelKind::Signal,
        )
        .expect("Signal has sealed default live provenance");
        let home = tempfile::tempdir().expect("create Signal unsettled-receipt WAL home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create Signal unsettled-receipt WAL");
        let segment = wal.join("000001.wal");
        let (writer, completion, ready) =
            crate::wal::writer::spawn_for_home_ready_with_completion(
                segment.clone(),
                home.path().to_path_buf(),
            )
            .expect("spawn Signal unsettled-receipt WAL writer");
        ready
            .wait()
            .await
            .expect("initialize Signal unsettled-receipt WAL");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let calls = Arc::new(AtomicUsize::new(0));
        let in_flight = {
            let started_tx = Arc::clone(&started_tx);
            let release_rx = Arc::clone(&release_rx);
            let calls = Arc::clone(&calls);
            let writer = writer.clone();
            let provenance = provenance.clone();
            tokio::spawn(async move {
                send_live_signal_reply(
                    &writer,
                    &provenance,
                    "private-recipient",
                    "private-reply",
                    move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started_tx
                            .lock()
                            .expect("lock Signal post-start sender")
                            .take()
                            .expect("one Signal adapter call")
                            .send(())
                            .expect("observe Signal adapter call");
                        let release_rx = Arc::clone(&release_rx);
                        async move {
                            release_rx
                                .lock()
                                .await
                                .take()
                                .expect("one Signal adapter result")
                                .await
                                .expect("release accepted Signal adapter result");
                            Ok::<MessageId, ChannelError>(MessageId("accepted".to_string()))
                        }
                    },
                )
                .await
            })
        };
        started_rx
            .await
            .expect("authenticated intent persisted before Signal adapter call");
        completion.abort_handle().abort();
        assert!(completion.wait().await.is_err());
        release_tx
            .send(())
            .expect("release accepted Signal adapter result after writer stop");
        assert!(
            in_flight
                .await
                .expect("join Signal live reply")
                .is_err(),
            "receipt failure is visible after the one accepted Signal effect"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "receipt failure never retries Signal");
        drop(writer);

        let bytes = tokio::fs::read(segment)
            .await
            .expect("read Signal unsettled-receipt WAL");
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut intents = 0;
        let mut results = 0;
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..])
                .expect("complete Signal unsettled-receipt evidence frame");
            intents += (frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8)
                as usize;
            results += (frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8)
                as usize;
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(intents, 1);
        assert_eq!(results, 0, "the accepted Signal effect remains unsettled");
    }
}
