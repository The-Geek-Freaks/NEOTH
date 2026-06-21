//! GOLD-FEAT-10 — Nostr channel adapter (RECEIVE + SEND), behind the
//! `nostr-channel` cargo feature. Uses `nostr-sdk` — a tokio-native client that
//! owns relay connection management, the WSS transport, and the NIP-44/NIP-59
//! cryptography behind NIP-17 private direct messages.
//!
//! [`NostrChannel::run`] builds a client signed by the operator's key, connects
//! to the configured relays, subscribes to gift-wrap events (kind 1059)
//! addressed to the operator, unwraps each into its inner rumor, feeds the DM
//! into the pipeline `handler`, and sends any reply back as a NIP-17 private
//! message to the original sender.
//!
//! ## Why a published `Client`, not a fresh connection per send
//!
//! Like the IRC adapter, the receive loop owns the connected client and
//! publishes a clone into a `OnceCell`; [`NostrChannel::send_text`] /
//! [`send_proactive`] send through that clone (the `nostr-sdk` `Client` is
//! internally reference-counted, so a clone shares the same relay pool). A
//! proactive send therefore only works once the receive loop is live (the
//! daemon spawns it at startup) — a send before then returns a clear
//! `Transport` error rather than opening a throwaway connection.
//!
//! ## Restart de-duplication
//!
//! Gift-wrap OUTER timestamps are randomized (up to ~2 days back) to resist
//! timing analysis, so a `since` filter on the wrap is unreliable. Instead we
//! filter on the INNER rumor's `created_at` (the genuine send time): a DM whose
//! rumor predates the moment this loop went live is skipped, so a restart does
//! not re-answer old messages.
//!
//! ## Operator prerequisite
//!
//! A Nostr secret key (`nsec1…` or hex) + a comma-separated relay list in
//! `credentials.yaml`. NEOTH dials OUT to the relays, so no public URL is
//! needed. Text only; media / NIP-17 file attachments are documented follow-ups.

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use nostr_sdk::prelude::*;
use tracing::{info, warn};

use crate::secret::SecretString;

use super::nostr_api::{map_nostr_dm, nostr_text_chunks};
use super::{Channel, ChannelError, MessageId, PipelineHandler};

/// Nostr adapter. Holds the operator's signing key + the relay list + the live
/// client handle (published by the receive loop once it connects).
pub struct NostrChannel {
    secret_key: SecretString,
    relays: Vec<String>,
    client: tokio::sync::OnceCell<Client>,
    /// D2 — operator sender allowlist (a 64-char hex pubkey). `None` ⇒ open.
    allowed_pubkey: Option<String>,
    /// D2 — WAL writer for the `0x3B CHANNEL_GATE_REJECTED` audit on a drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl NostrChannel {
    /// Build the adapter. Construction is cheap + does no I/O — the connection
    /// happens in [`Self::run`]. `relays_csv` is a comma-separated list of WSS
    /// relay URLs (e.g. `wss://relay.damus.io,wss://nos.lol`).
    pub fn new(secret_key: SecretString, relays_csv: impl AsRef<str>) -> Self {
        let relays: Vec<String> = relays_csv
            .as_ref()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Self {
            secret_key,
            relays,
            client: tokio::sync::OnceCell::new(),
            allowed_pubkey: None,
            gate_writer: None,
        }
    }

    /// D2 — bind the operator sender allowlist + the gate's audit writer. An
    /// unset allowlist (`None`) leaves the channel open (any sender).
    pub fn with_allowlist(
        mut self,
        allowed_pubkey: Option<String>,
        gate_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        self.allowed_pubkey = allowed_pubkey;
        self.gate_writer = Some(gate_writer);
        self
    }

    /// Parse the operator's secret key (accepts `nsec1…` bech32 or 64-char hex).
    fn keys(&self) -> Result<Keys> {
        Keys::parse(self.secret_key.expose())
            .context("parse nostr secret key (expected nsec1… or hex)")
    }
}

#[async_trait]
impl Channel for NostrChannel {
    fn name(&self) -> &'static str {
        "nostr"
    }

    /// Connect to the relays, subscribe to inbound gift-wrapped DMs, publish the
    /// client handle, then stream + unwrap NIP-17 messages into the pipeline
    /// until the daemon aborts the spawned task. A fatal key/connect error
    /// returns `Err` (the spawn loop logs it, no restart-spin on a broken
    /// config); transient relay drops are handled by the SDK's relay pool.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let keys = self.keys()?;
        let my_pubkey = keys.public_key();
        let client = Client::builder().signer(keys).build();
        for relay in &self.relays {
            client
                .add_relay(relay.as_str())
                .await
                .with_context(|| format!("add nostr relay {relay}"))?;
        }
        if self.relays.is_empty() {
            anyhow::bail!("nostr: no relays configured (set nostr_relays)");
        }
        client.connect().await;
        // Publish the (ref-counted) client so `send_text` can send while the
        // loop runs.
        let _ = self.client.set(client.clone());

        // Subscribe to gift wraps (kind 1059) p-tagged to us.
        let filter = Filter::new().kind(Kind::GiftWrap).pubkey(my_pubkey);
        client
            .subscribe(filter, None)
            .await
            .context("nostr subscribe to gift wraps")?;

        // Anything whose INNER rumor predates this moment is an old DM — skip it
        // so a restart never re-answers history.
        let start_ts = crate::time::now_unix_secs();
        let mut notifications = client.notifications();
        info!(relays = self.relays.len(), "nostr adapter live");

        while let Ok(notification) = notifications.recv().await {
            let RelayPoolNotification::Event { event, .. } = notification else {
                continue;
            };
            if event.kind != Kind::GiftWrap {
                continue;
            }
            let unwrapped = match client.unwrap_gift_wrap(&event).await {
                Ok(u) => u,
                Err(e) => {
                    warn!(error = %e, "nostr gift-wrap unwrap failed; skipping");
                    continue;
                }
            };
            let sender = unwrapped.sender;
            // D2 — drop + audit a sender not on the operator allowlist before
            // the pipeline sees the message (open when None).
            if super::sender_blocked_by_allowlist(
                self.allowed_pubkey.as_deref(),
                &sender.to_hex(),
                self.gate_writer.as_ref(),
                "nostr",
            )
            .await
            {
                continue;
            }
            let rumor = unwrapped.rumor;
            let rumor_ts = rumor.created_at.as_secs();
            if rumor_ts < start_ts {
                continue; // old DM surfaced on restart — do not re-answer
            }
            let Some(inbound) = map_nostr_dm(&sender.to_hex(), &rumor.content, rumor_ts) else {
                continue;
            };
            match handler(inbound).await {
                Ok(Some(out)) => {
                    for chunk in nostr_text_chunks(&out.text) {
                        if let Err(e) = client.send_private_msg(sender, chunk, []).await {
                            warn!(error = %e, "nostr DM reply failed (dropped)");
                            break;
                        }
                    }
                }
                Ok(None) => {} // pipeline chose to stay silent
                Err(e) => warn!(error = %e, "nostr pipeline handler errored; skipping message"),
            }
        }
        Ok(())
    }

    /// Send a NIP-17 private message to `chat_id` (the recipient's pubkey, hex or
    /// `npub1…`) via the live client. Long text is split into relay-safe chunks.
    /// Returns a `Transport` error if the receive loop has not connected yet.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let client = self.client.get().ok_or_else(|| {
            ChannelError::Transport(
                "nostr not connected (the receive loop must be live to send)".into(),
            )
        })?;
        let recipient = PublicKey::parse(chat_id)
            .map_err(|e| ChannelError::Transport(format!("invalid nostr recipient pubkey: {e}")))?;
        for chunk in nostr_text_chunks(text) {
            client
                .send_private_msg(recipient, chunk, [])
                .await
                .map_err(|e| ChannelError::Transport(format!("nostr send: {e}")))?;
        }
        Ok(MessageId("sent".to_string()))
    }

    /// Proactive send delegates to [`Self::send_text`] — a daemon-initiated DM is
    /// identical to a reply. The operator proactive gate is the caller's
    /// responsibility per the C-11 trait contract.
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

    fn ch() -> NostrChannel {
        NostrChannel::new(
            SecretString::from("nsec1exampledummykeydummy"),
            "wss://relay.damus.io, wss://nos.lol ,",
        )
    }

    #[test]
    fn adapter_reports_nostr_name() {
        assert_eq!(ch().name(), "nostr");
    }

    #[test]
    fn new_parses_relay_csv_trimming_blanks() {
        let c = ch();
        assert_eq!(
            c.relays,
            vec!["wss://relay.damus.io", "wss://nos.lol"],
            "trims spaces + drops the trailing empty"
        );
    }

    #[tokio::test]
    async fn send_before_connect_is_a_clear_transport_error() {
        let c = ch();
        let err = c
            .send_text(
                "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
                "hi",
            )
            .await
            .unwrap_err();
        match err {
            ChannelError::Transport(m) => assert!(m.contains("not connected")),
            other => panic!("expected a not-connected Transport error, got {other:?}"),
        }
    }
}
