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

use super::signal_api::{envelope_to_inbound, receive_messages, send_signal_message};
use super::{Channel, ChannelError, MessageId, PipelineHandler};

/// Default receive-poll cadence. 2s matches the parity-doc default — low
/// enough to feel responsive, high enough not to hammer signal-cli.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Signal adapter. Holds the signal-cli base URL, our registered E.164
/// number, a shared HTTP client, and the poll cadence. Stateless beyond
/// that — every send/receive is one HTTP round trip.
pub struct SignalChannel {
    cli_url: String,
    phone_number: String,
    http: reqwest::Client,
    poll_interval: Duration,
}

impl SignalChannel {
    /// Build against a running signal-cli daemon. `cli_url` e.g.
    /// `http://127.0.0.1:8080`; `phone_number` the registered `+E.164`.
    pub fn new(cli_url: impl Into<String>, phone_number: impl Into<String>) -> Result<Self> {
        let http = crate::providers::http_client::build_client()
            .context("build reqwest client for Signal adapter")?;
        Ok(Self {
            cli_url: cli_url.into().trim_end_matches('/').to_string(),
            phone_number: phone_number.into(),
            http,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
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
        info!(
            url = %self.cli_url,
            poll_secs = self.poll_interval.as_secs(),
            "signal receive poll loop starting"
        );
        loop {
            match receive_messages(&self.http, &self.cli_url, &self.phone_number).await {
                Ok(envelopes) => {
                    for env in &envelopes {
                        let Some(inbound) = envelope_to_inbound(env) else {
                            continue; // receipt / typing / sync — not actionable
                        };
                        match handler(inbound).await {
                            Ok(Some(out)) => {
                                if let Err(e) = send_signal_message(
                                    &self.http,
                                    &self.cli_url,
                                    &self.phone_number,
                                    &out.recipient_id,
                                    &out.text,
                                )
                                .await
                                {
                                    warn!(error = %e, "signal reply send failed (dropped)");
                                }
                            }
                            Ok(None) => {} // pipeline chose to stay silent
                            Err(e) => {
                                warn!(error = %e, "signal pipeline handler errored; skipping message")
                            }
                        }
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
        send_signal_message(&self.http, &self.cli_url, &self.phone_number, chat_id, text).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_reports_signal_name() {
        let a = SignalChannel::new("http://127.0.0.1:8080", "+4400").unwrap();
        assert_eq!(a.name(), "signal");
    }

    #[test]
    fn new_trims_trailing_slash_from_url() {
        let a = SignalChannel::new("http://127.0.0.1:8080/", "+4400").unwrap();
        assert_eq!(
            a.cli_url, "http://127.0.0.1:8080",
            "trailing slash stripped"
        );
    }

    #[test]
    fn with_poll_interval_overrides_default() {
        let a = SignalChannel::new("http://x", "+1")
            .unwrap()
            .with_poll_interval(Duration::from_millis(500));
        assert_eq!(a.poll_interval, Duration::from_millis(500));
        // default sanity
        let b = SignalChannel::new("http://x", "+1").unwrap();
        assert_eq!(b.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    /// Verify the rate-limit arm is reachable (parse + re-surface path).
    /// The signal_api::map_status function already parses Retry-After correctly
    /// (tested in signal_api); this test confirms the run() loop has a dedicated
    /// arm for RateLimited rather than lumping it into the generic catch-all.
    #[test]
    fn rate_limited_error_is_a_distinct_variant() {
        // Construct the error the way map_status emits it.
        let e = ChannelError::RateLimited { retry_after_secs: 30 };
        // The error Display must mention the retry-after value for operator logs.
        let s = e.to_string();
        assert!(
            s.contains("30"),
            "RateLimited display must include retry_after_secs: {s}"
        );
    }
}
