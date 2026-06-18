//! GOLD-FEAT-10 — Matrix channel adapter (RECEIVE + SEND) over `matrix-sdk`
//! with end-to-end encryption. Behind the `matrix-channel` cargo feature.
//!
//! [`MatrixChannel::run`] builds (or restores) an E2EE-capable client, drains
//! the backlog once so a first-ever start does not reply to history, then
//! registers two event handlers and drives the live `/sync` loop:
//!   * an **auto-join** handler so the bot joins rooms it is invited to, and
//!   * a **message** handler that maps each inbound `m.room.message` (text)
//!     to an [`InboundMessage`], runs the pipeline `handler`, and posts any
//!     reply back into the same room.
//!
//! [`MatrixChannel::send_text`] / [`send_proactive`](MatrixChannel::send_proactive)
//! resolve a room id and send into it directly, for the proactive-delivery
//! path the receive loop's handler closure cannot reach.
//!
//! ## Scope (no shortcuts, but bounded)
//!
//! Text messages are fully handled. **Media** (encrypted attachments need a
//! download + decrypt step), **threads** (`m.thread` relations), and **edits**
//! (`m.replace`) are documented follow-ups, mirrored on how the Signal adapter
//! deferred its SSE receive path — each is a separate body of work, not a
//! corner cut on the core text round-trip.
//!
//! ## Operator prerequisite
//!
//! A homeserver URL + a bot user id + (for the one-time login) a password,
//! all in `credentials.yaml`. After the first login the device session
//! persists to `<store>/neoth-matrix-session.json` and the password is no
//! longer read. See [`super::matrix_client`] for the session lifecycle.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use matrix_sdk::{
    Client, Room, RoomState,
    ruma::{
        RoomId,
        events::room::{
            member::{MembershipState, StrippedRoomMemberEvent},
            message::{MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent},
        },
    },
};
use tracing::{error, info, warn};

use crate::secret::SecretString;

use super::matrix_client;
use super::{Channel, ChannelError, ChannelKind, InboundMessage, MessageId, PipelineHandler};

/// Matrix adapter. Holds the connection parameters + a lazily-initialized,
/// logged-in [`Client`] shared by the receive loop and the send paths. The
/// client is built once on first use (by whichever of `run` / `send_text`
/// runs first) so a proactive send does not need the receive loop to be
/// running, and the receive loop does not pay for a second login.
pub struct MatrixChannel {
    homeserver: String,
    user_id: String,
    password: Option<SecretString>,
    store_path: PathBuf,
    client: tokio::sync::OnceCell<Client>,
}

impl MatrixChannel {
    /// Build against a homeserver. `store_path` defaults to
    /// `~/.neoth/matrix_store/` when `None`. Construction is cheap + does no
    /// I/O — the network login happens lazily on first [`Self::client`].
    pub fn new(
        homeserver: impl Into<String>,
        user_id: impl Into<String>,
        password: Option<SecretString>,
        store_path: Option<PathBuf>,
    ) -> Self {
        Self {
            homeserver: homeserver.into().trim_end_matches('/').to_string(),
            user_id: user_id.into(),
            password,
            store_path: store_path.unwrap_or_else(matrix_client::default_store_path),
            client: tokio::sync::OnceCell::new(),
        }
    }

    /// Lazily build + authenticate the shared client. On error the cell stays
    /// uninitialized, so a later call retries (rides out a transient
    /// homeserver outage at startup).
    async fn client(&self) -> Result<&Client> {
        self.client
            .get_or_try_init(|| async {
                let client =
                    matrix_client::build_client(&self.homeserver, &self.store_path).await?;
                matrix_client::login_or_restore(
                    &client,
                    &self.store_path,
                    &self.user_id,
                    self.password.as_ref().map(|p| p.expose()),
                )
                .await?;
                Ok::<_, anyhow::Error>(client)
            })
            .await
    }
}

/// Map the channel-native primitives of an inbound text message to an
/// [`InboundMessage`]. Split out from the handler closure so it is unit
/// testable without constructing ruma event values. `ts_ms` is the raw
/// `origin_server_ts` (Matrix is always ms since the unix epoch); the
/// `channel_ts_unix` seconds value clamps a (spec-illegal but defensive)
/// negative timestamp to 0.
fn build_inbound(
    room_id: &str,
    sender: &str,
    event_id: &str,
    ts_ms: i64,
    body: &str,
) -> InboundMessage {
    InboundMessage {
        channel: ChannelKind::Matrix,
        chat_id: room_id.to_string(),
        thread_id: None,
        sender_id: sender.to_string(),
        sender_display: None,
        text: Some(body.to_string()),
        media: None,
        reply_to: None,
        message_id: Some(event_id.to_string()),
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: (ts_ms.max(0) / 1000) as u64,
        raw_ts_ms: Some(ts_ms),
        human_uuid: None,
    }
}

#[async_trait]
impl Channel for MatrixChannel {
    fn name(&self) -> &'static str {
        "matrix"
    }

    /// Build/restore the client, drain the backlog once, register the
    /// auto-join + message handlers, then run the live sync loop until the
    /// daemon aborts the spawned task at shutdown. A fatal client/auth error
    /// returns `Err` (the spawn loop logs it and does not restart-spin a
    /// broken config); the live `sync` loop itself retries transient network
    /// errors internally per matrix-sdk's default retry policy.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let client = self.client().await.context("matrix client init")?;
        info!(
            user = %self.user_id,
            homeserver = %self.homeserver,
            "matrix adapter starting"
        );

        // Auto-join rooms we are invited to. Registered BEFORE the initial
        // sync so an invite pending at startup is honoured on the first poll.
        client.add_event_handler(
            |ev: StrippedRoomMemberEvent, room: Room, client: Client| async move {
                // Only act on an invite addressed to US.
                let Some(me) = client.user_id() else {
                    return;
                };
                if ev.state_key.as_str() != me.as_str()
                    || ev.content.membership != MembershipState::Invite
                {
                    return;
                }
                info!(room = %room.room_id(), "matrix: auto-joining invited room");
                // Retry with backoff — the inviting server can lag behind the
                // invite event.
                let mut delay_secs = 2u64;
                while let Err(e) = room.join().await {
                    warn!(room = %room.room_id(), error = %e, "matrix: join failed; retrying");
                    if delay_secs > 60 {
                        error!(room = %room.room_id(), "matrix: giving up auto-join after retries");
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    delay_secs *= 2;
                }
            },
        );

        // Drain the backlog WITHOUT the message handler so a first-ever start
        // (empty store) does not reply to historical messages. With a
        // persisted store the sync token resumes, so this is cheap on later
        // starts. The auto-join handler IS active here, so startup invites
        // are still joined during this initial sync.
        client
            .sync_once(matrix_client::sync_settings())
            .await
            .context("matrix initial sync")?;

        // Register the message handler and run the live sync loop. The
        // pipeline handler is shared into the per-event closure via `Arc`
        // (matrix-sdk clones the handler per event; `PipelineHandler` itself
        // is not `Clone`).
        let handler = Arc::new(handler);
        client.add_event_handler(
            move |ev: OriginalSyncRoomMessageEvent, room: Room, client: Client| {
                let handler = handler.clone();
                async move {
                    // Only joined rooms (skip invited/left/knocked).
                    if room.state() != RoomState::Joined {
                        return;
                    }
                    // Never react to our own echo — would loop forever.
                    if let Some(me) = client.user_id() {
                        if ev.sender.as_str() == me.as_str() {
                            return;
                        }
                    }
                    // Text only for now (media/threads/edits are follow-ups).
                    let MessageType::Text(text) = &ev.content.msgtype else {
                        return;
                    };
                    let ts_ms = u64::from(ev.origin_server_ts.get()) as i64;
                    let inbound = build_inbound(
                        room.room_id().as_str(),
                        ev.sender.as_str(),
                        ev.event_id.as_str(),
                        ts_ms,
                        &text.body,
                    );
                    match handler(inbound).await {
                        Ok(Some(out)) => {
                            if let Err(e) = room
                                .send(RoomMessageEventContent::text_plain(out.text))
                                .await
                            {
                                warn!(room = %room.room_id(), error = %e, "matrix reply send failed (dropped)");
                            }
                        }
                        Ok(None) => {} // pipeline chose to stay silent
                        Err(e) => {
                            warn!(error = %e, "matrix pipeline handler errored; skipping message");
                        }
                    }
                }
            },
        );

        info!("matrix: live sync loop started");
        client
            .sync(matrix_client::sync_settings())
            .await
            .context("matrix sync loop")?;
        Ok(())
    }

    /// Send a plain-text message into a room. `chat_id` is the Matrix room id
    /// (the inbound `chat_id`, so replies route back to the same room). The
    /// bot must already be joined to the room — otherwise the homeserver has
    /// no room handle and we surface a clear `Transport` error rather than
    /// silently dropping.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let client = self
            .client()
            .await
            .map_err(|e| ChannelError::Auth(e.to_string()))?;
        let room_id = RoomId::parse(chat_id).map_err(|e| {
            ChannelError::Transport(format!("invalid matrix room id {chat_id}: {e}"))
        })?;
        let room = client.get_room(&room_id).ok_or_else(|| {
            ChannelError::Transport(format!("not joined to matrix room {chat_id}"))
        })?;
        let resp = room
            .send(RoomMessageEventContent::text_plain(text))
            .await
            .map_err(|e| ChannelError::Transport(format!("matrix send: {e}")))?;
        Ok(MessageId(resp.response.event_id.to_string()))
    }

    /// Proactive send delegates to [`Self::send_text`] — sending into a room is
    /// identical for a reply vs a daemon-initiated message. The operator gate
    /// (`FreedomConfig::proactive.enabled`) is the CALLER's responsibility per
    /// the C-11 trait contract.
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
    fn adapter_reports_matrix_name() {
        let a = MatrixChannel::new("https://matrix.org", "@bot:matrix.org", None, None);
        assert_eq!(a.name(), "matrix");
    }

    #[test]
    fn new_trims_trailing_slash_from_homeserver() {
        let a = MatrixChannel::new("https://matrix.org/", "@bot:matrix.org", None, None);
        assert_eq!(
            a.homeserver, "https://matrix.org",
            "trailing slash stripped"
        );
    }

    #[test]
    fn new_defaults_store_path_when_none() {
        let a = MatrixChannel::new("https://m.org", "@b:m.org", None, None);
        assert_eq!(
            a.store_path.file_name().and_then(|s| s.to_str()),
            Some("matrix_store")
        );
    }

    #[test]
    fn new_honours_explicit_store_path() {
        let custom = PathBuf::from("/tmp/neoth-matrix-test-store");
        let a = MatrixChannel::new("https://m.org", "@b:m.org", None, Some(custom.clone()));
        assert_eq!(a.store_path, custom);
    }

    #[test]
    fn build_inbound_maps_text_message_fields() {
        let m = build_inbound(
            "!room:server.org",
            "@alice:server.org",
            "$evt123",
            1_700_000_000_000, // ms
            "hello neoth",
        );
        assert_eq!(m.channel, ChannelKind::Matrix);
        assert_eq!(m.chat_id, "!room:server.org");
        assert_eq!(m.sender_id, "@alice:server.org");
        assert_eq!(m.message_id.as_deref(), Some("$evt123"));
        assert_eq!(m.text.as_deref(), Some("hello neoth"));
        // ms → s conversion
        assert_eq!(m.channel_ts_unix, 1_700_000_000);
        assert_eq!(m.raw_ts_ms, Some(1_700_000_000_000));
        // text-only mapping leaves the rich fields unset
        assert!(m.media.is_none());
        assert!(m.thread_id.is_none());
        assert!(m.mention_kind.is_none());
    }

    #[test]
    fn build_inbound_clamps_negative_timestamp_to_zero() {
        // A spec-illegal negative ts must not underflow the u64 seconds value.
        let m = build_inbound("!r:s", "@a:s", "$e", -5, "x");
        assert_eq!(m.channel_ts_unix, 0);
        assert_eq!(m.raw_ts_ms, Some(-5));
    }
}
