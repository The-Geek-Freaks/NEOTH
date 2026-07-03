//! GOLD-FEAT-10 — IRC channel adapter (RECEIVE + SEND), behind the
//! `irc-channel` cargo feature. Uses the `irc` crate (aatxe) — a tokio-native
//! IRC client that owns the wire protocol, PING/PONG keep-alive, and reconnect.
//!
//! [`IrcChannel::run`] connects (`Client::from_config`), identifies + joins the
//! configured channels, then streams `PRIVMSG`s into the pipeline `handler` and
//! posts any reply back to the originating channel/nick (split into IRC-safe
//! lines by [`super::irc_api::irc_lines`]).
//!
//! ## Why a stored `Sender`, not a shared `Client`
//!
//! The irc crate's `Client::stream` takes `&mut self`, so the connected client
//! can't be shared behind a `&` reference like the Matrix client. Instead the
//! receive loop OWNS the client and publishes its clonable [`Sender`] into a
//! `OnceCell`; [`IrcChannel::send_text`] / [`send_proactive`] send through that
//! sender. A proactive send therefore only works once the receive loop is live
//! (the daemon spawns it at startup) — a send before then returns a clear
//! `Transport` error rather than opening a throwaway connection.
//!
//! ## Operator prerequisite
//!
//! A server host + bot nick (+ optional NickServ/bouncer password + channels)
//! in `credentials.yaml`. NEOTH dials OUT to the server, so no public URL is
//! needed (unlike the webhook channels). Text only; CTCP/DCC/actions are
//! documented follow-ups, not corner-cuts on the core round-trip.
//!
//! ## Spoofing characteristics
//!
//! IRC sender identity is the `nick!user@host` prefix — on public networks a
//! nick is claimable by anyone the moment its holder disconnects (`/nick`
//! race), so `irc_allowed_nick` alone is a WEAK gate. Hardened mode: set
//! `irc_allowed_account` and the adapter requests the IRCv3 `account-tag`
//! capability; inbound messages must then carry an `account=<name>` tag
//! asserted by the network's services (NickServ/SASL) matching the allowlist
//! — messages without the tag (unidentified senders, networks without the
//! cap) are dropped + audited (0x3B). Twitch does not need this: Twitch
//! authenticates every connection, nicks can't be claimed by strangers.

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use irc::client::Sender;
use irc::client::prelude::{Client, Command, Config};
use tracing::{info, warn};

use crate::secret::SecretString;

use super::irc_api::{irc_lines, map_irc_privmsg};
use super::{Channel, ChannelError, ChannelKind, MessageId, PipelineHandler};

/// IRC adapter. Holds the connection config + the live send handle (published by
/// the receive loop once it connects). The same adapter serves **Twitch chat**
/// (which is IRC under the hood) via [`Self::for_twitch`] — `kind` records which
/// so inbound messages, routing, and the WAL see the right channel family.
pub struct IrcChannel {
    config: Config,
    nick: String,
    sender: tokio::sync::OnceCell<Sender>,
    kind: ChannelKind,
    /// D2 — operator sender allowlist (a nick). `None` ⇒ open.
    allowed_nick: Option<String>,
    /// B9 — services-account allowlist (IRCv3 `account-tag`). `None` ⇒
    /// nick-only gating; set ⇒ inbound messages must carry a matching
    /// `account=` tag (see module docs, "Spoofing characteristics").
    allowed_account: Option<String>,
    /// D2 — WAL writer for the `0x3B CHANNEL_GATE_REJECTED` audit on a drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl IrcChannel {
    /// Build the adapter. Construction is cheap + does no I/O — the connection
    /// happens in [`Self::run`]. `channels_csv` is a comma-separated channel
    /// list (e.g. `#neoth,#dev`).
    pub fn new(
        server: impl Into<String>,
        port: u16,
        nick: impl Into<String>,
        password: Option<SecretString>,
        channels_csv: impl AsRef<str>,
        use_tls: bool,
    ) -> Self {
        let nick = nick.into();
        let channels: Vec<String> = channels_csv
            .as_ref()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let config = Config {
            nickname: Some(nick.clone()),
            server: Some(server.into()),
            port: Some(port),
            use_tls: Some(use_tls),
            password: password.map(|p| p.expose().to_string()),
            channels,
            ..Config::default()
        };
        Self {
            config,
            nick,
            sender: tokio::sync::OnceCell::new(),
            kind: ChannelKind::Irc,
            allowed_nick: None,
            allowed_account: None,
            gate_writer: None,
        }
    }

    /// D2 — bind the operator sender allowlist + the gate's audit writer. An
    /// unset allowlist (`None`) leaves the channel open (any sender).
    pub fn with_allowlist(
        mut self,
        allowed_nick: Option<String>,
        gate_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        self.allowed_nick = allowed_nick;
        self.gate_writer = Some(gate_writer);
        self
    }

    /// B9 spoof-hardening — require the IRCv3 `account-tag` to match this
    /// services account on every inbound message. `None` ⇒ nick-only gating.
    pub fn with_allowed_account(mut self, allowed_account: Option<String>) -> Self {
        self.allowed_account = allowed_account;
        self
    }

    /// Configure this adapter for **Twitch chat** — which is IRC under the hood
    /// (`irc.chat.twitch.tv:6697`, TLS). The operator supplies the bot's Twitch
    /// username + an OAuth token carrying `chat:read` (+ `chat:edit` to send)
    /// scopes; NEOTH prepends the required `oauth:` prefix. Rich Twitch features
    /// (typed tags, sub/raid events) are out of scope — this is the basic chat
    /// round-trip, identical to the IRC path.
    pub fn for_twitch(
        username: impl Into<String>,
        oauth_token: SecretString,
        channels_csv: impl AsRef<str>,
    ) -> Self {
        // Twitch logins + channel names are lowercase by convention.
        let username = username.into().to_lowercase();
        let channels = channels_csv.as_ref().to_lowercase();
        let password = SecretString::from(format!("oauth:{}", oauth_token.expose()));
        let mut ch = Self::new(
            "irc.chat.twitch.tv",
            6697,
            username,
            Some(password),
            channels,
            true,
        );
        ch.kind = ChannelKind::Twitch;
        ch
    }
}

/// Connect + identify a client. Owned (the caller's receive loop needs `&mut`
/// for `stream()`). `extra_caps` are requested BEFORE `identify()` — the irc
/// crate's `identify()` sends `CAP END`, and a `CAP REQ` issued after that is
/// only honoured on networks with IRCv3.2 post-registration re-negotiation;
/// requesting inside the negotiation window works everywhere.
async fn connect(config: &Config, extra_caps: &[irc::client::prelude::Capability]) -> Result<Client> {
    let client = Client::from_config(config.clone())
        .await
        .context("irc connect")?;
    if !extra_caps.is_empty() {
        client
            .send_cap_req(extra_caps)
            .context("irc cap-req (pre-identify)")?;
    }
    client.identify().context("irc identify")?;
    Ok(client)
}

fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

/// B9 — extract the IRCv3 `account=` tag from a raw message. `None` when the
/// message carries no tags or no account tag (unidentified sender / network
/// without the cap). A present-but-valueless tag maps to `""` — which a set
/// allowlist always rejects.
fn account_tag_value(message: &irc::proto::Message) -> Option<String> {
    message
        .tags
        .as_ref()?
        .iter()
        .find_map(|tag| (tag.0 == "account").then(|| tag.1.clone().unwrap_or_default()))
}

#[async_trait]
impl Channel for IrcChannel {
    fn name(&self) -> &'static str {
        self.kind.as_str()
    }

    /// Connect, identify + join, publish the send handle, then stream inbound
    /// `PRIVMSG`s into the pipeline until the daemon aborts the spawned task. A
    /// fatal connect/auth error returns `Err` (the spawn loop logs it, no
    /// restart-spin on a broken config); the irc crate retries transient
    /// line-level errors internally.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        // B9 — hardened mode needs the server to attach `account=` tags to
        // inbound messages. The cap is requested inside the registration
        // window (before `CAP END`); a network that doesn't support it simply
        // never tags, and every message is then dropped by the account gate
        // below (fail-closed, never fail-open).
        let caps: &[irc::client::prelude::Capability] = if self.allowed_account.is_some() {
            &[irc::client::prelude::Capability::AccountTag]
        } else {
            &[]
        };
        let mut client = connect(&self.config, caps)
            .await
            .context("irc client init")?;
        // Publish the clonable send handle so `send_text` (a `&self` method that
        // can't reach this owned client) can send while the loop runs.
        let sender = client.sender();
        let _ = self.sender.set(sender.clone());
        let mut stream = client.stream().context("irc stream")?;
        info!(nick = %self.nick, "irc adapter live");
        while let Some(message) = stream.next().await.transpose().context("irc stream recv")? {
            let Command::PRIVMSG(target, text) = &message.command else {
                continue;
            };
            let source_nick = message.source_nickname();
            let Some(mut inbound) =
                map_irc_privmsg(target, text, source_nick, &self.nick, now_unix())
            else {
                continue;
            };
            // Twitch chat reuses the IRC mapping; stamp the real channel family so
            // routing / formatting / WAL see "twitch", not "irc".
            inbound.channel = self.kind;
            // B9 — hardened account gate first: with `irc_allowed_account`
            // set, the message must carry a services-asserted `account=` tag
            // matching the allowlist. Missing tag ⇒ blocked (fail-closed) —
            // an unidentified sender or a network without the cap never
            // passes. The empty-string sentinel can't collide: a set
            // allowlist is non-empty, so "" ≠ allowed always blocks.
            if let Some(allowed) = self.allowed_account.as_deref() {
                let account = account_tag_value(&message).unwrap_or_default();
                if super::sender_blocked_by_allowlist(
                    Some(allowed),
                    &account,
                    self.gate_writer.as_ref(),
                    self.kind.as_str(),
                )
                .await
                {
                    continue;
                }
            }
            // D2 — drop + audit a sender not on the operator allowlist before
            // the pipeline sees the message (open when None).
            if super::sender_blocked_by_allowlist(
                self.allowed_nick.as_deref(),
                &inbound.sender_id,
                self.gate_writer.as_ref(),
                self.kind.as_str(),
            )
            .await
            {
                continue;
            }
            let reply_to = inbound.chat_id.clone();
            match handler(inbound).await {
                Ok(Some(out)) => {
                    // IRC is line-oriented + 512-byte-capped — split the reply
                    // into safe lines, one PRIVMSG each.
                    for line in irc_lines(&out.text) {
                        if let Err(e) = sender.send_privmsg(&reply_to, &line) {
                            warn!(error = %e, "irc reply send failed (dropped)");
                            break;
                        }
                    }
                }
                Ok(None) => {} // pipeline chose to stay silent
                Err(e) => warn!(error = %e, "irc pipeline handler errored; skipping message"),
            }
        }
        Ok(())
    }

    /// Send a plain-text message to `chat_id` (a channel `#room` or a nick) via
    /// the live send handle. Long text is split into IRC-safe lines. Returns a
    /// `Transport` error if the receive loop has not connected yet.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let sender = self.sender.get().ok_or_else(|| {
            ChannelError::Transport(
                "irc not connected (the receive loop must be live to send)".into(),
            )
        })?;
        for line in irc_lines(text) {
            sender
                .send_privmsg(chat_id, &line)
                .map_err(|e| ChannelError::Transport(format!("irc send: {e}")))?;
        }
        Ok(MessageId("sent".to_string()))
    }

    /// Proactive send delegates to [`Self::send_text`] — a daemon-initiated
    /// PRIVMSG is identical to a reply. The operator proactive gate is the
    /// caller's responsibility per the C-11 trait contract.
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

    fn ch() -> IrcChannel {
        IrcChannel::new("irc.example.org", 6697, "neoth", None, "#a, #b ,", true)
    }

    fn msg_with_tags(tags: Option<Vec<irc::proto::message::Tag>>) -> irc::proto::Message {
        irc::proto::Message {
            tags,
            prefix: None,
            command: Command::PRIVMSG("#a".to_string(), "hi".to_string()),
        }
    }

    #[test]
    fn account_tag_extracted_when_present() {
        use irc::proto::message::Tag;
        let m = msg_with_tags(Some(vec![
            Tag("time".to_string(), Some("x".to_string())),
            Tag("account".to_string(), Some("alex".to_string())),
        ]));
        assert_eq!(account_tag_value(&m).as_deref(), Some("alex"));
    }

    #[test]
    fn account_tag_absent_or_valueless_fails_closed() {
        use irc::proto::message::Tag;
        // no tags at all → None → gate sees "" → blocked by any allowlist
        assert_eq!(account_tag_value(&msg_with_tags(None)), None);
        // tags but no account tag → None
        let m = msg_with_tags(Some(vec![Tag("time".to_string(), None)]));
        assert_eq!(account_tag_value(&m), None);
        // account tag with no value → "" (a set allowlist never matches "")
        let m = msg_with_tags(Some(vec![Tag("account".to_string(), None)]));
        assert_eq!(account_tag_value(&m).as_deref(), Some(""));
    }

    #[test]
    fn with_allowed_account_stores_allowlist() {
        let c = ch().with_allowed_account(Some("alex".to_string()));
        assert_eq!(c.allowed_account.as_deref(), Some("alex"));
        assert!(ch().allowed_account.is_none(), "default = nick-only gating");
    }

    #[test]
    fn adapter_reports_irc_name() {
        assert_eq!(ch().name(), "irc");
    }

    #[test]
    fn new_parses_channel_csv_trimming_blanks() {
        let c = ch();
        assert_eq!(
            c.config.channels,
            vec!["#a", "#b"],
            "trims spaces + drops the trailing empty"
        );
    }

    #[test]
    fn new_carries_nick_port_and_tls_into_config() {
        let c = ch();
        assert_eq!(c.nick, "neoth");
        assert_eq!(c.config.nickname.as_deref(), Some("neoth"));
        assert_eq!(c.config.port, Some(6697));
        assert_eq!(c.config.use_tls, Some(true));
        assert_eq!(c.config.password, None);
    }

    #[test]
    fn password_is_exposed_into_config() {
        let c = IrcChannel::new(
            "h",
            6667,
            "n",
            Some(SecretString::from("hunter2")),
            "#x",
            false,
        );
        assert_eq!(c.config.password.as_deref(), Some("hunter2"));
        assert_eq!(c.config.use_tls, Some(false));
    }

    #[tokio::test]
    async fn send_before_connect_is_a_clear_transport_error() {
        let c = ch();
        let err = c.send_text("#a", "hi").await.unwrap_err();
        match err {
            ChannelError::Transport(m) => assert!(m.contains("not connected")),
            other => panic!("expected a not-connected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn twitch_adapter_reports_twitch_name() {
        let c = IrcChannel::for_twitch("MyBot", SecretString::from("tok"), "#chan");
        assert_eq!(
            c.name(),
            "twitch",
            "Twitch reuses the IRC adapter but reports its own kind"
        );
    }

    #[test]
    fn for_twitch_builds_twitch_server_oauth_and_lowercases() {
        let c = IrcChannel::for_twitch("MyBot", SecretString::from("abc"), "#MyChannel, #Two");
        assert_eq!(c.config.server.as_deref(), Some("irc.chat.twitch.tv"));
        assert_eq!(c.config.port, Some(6697));
        assert_eq!(c.config.use_tls, Some(true));
        assert_eq!(
            c.config.nickname.as_deref(),
            Some("mybot"),
            "username lowercased"
        );
        assert_eq!(
            c.config.password.as_deref(),
            Some("oauth:abc"),
            "oauth: prefix prepended"
        );
        assert_eq!(
            c.config.channels,
            vec!["#mychannel", "#two"],
            "channels lowercased + parsed"
        );
    }
}
