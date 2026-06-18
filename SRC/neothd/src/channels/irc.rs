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
        }
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
/// for `stream()`).
async fn connect(config: &Config) -> Result<Client> {
    let client = Client::from_config(config.clone())
        .await
        .context("irc connect")?;
    client.identify().context("irc identify")?;
    Ok(client)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        let mut client = connect(&self.config).await.context("irc client init")?;
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
