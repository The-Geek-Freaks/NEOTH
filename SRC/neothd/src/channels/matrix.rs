//! GOLD-FEAT-10 — Matrix channel adapter (RECEIVE + SEND) over `matrix-sdk`
//! with an explicit encrypted-room policy. Behind the `matrix-channel` cargo
//! feature.
//!
//! [`MatrixChannel::run`] builds (or restores) an E2EE-capable client, drains
//! the backlog once so a first-ever start does not reply to history, then
//! registers two event handlers and drives the live `/sync` loop:
//!   * an **invite gate** that joins only allowlisted rooms/inviters, and
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
//! A homeserver URL + bot user id + access token or one-time password, all in
//! `credentials.yaml`. After authentication the device session persists to
//! `<store>/neoth-matrix-session.json`. By default only encrypted rooms are
//! accepted/sent to (`matrix_require_encryption: false` is the explicit
//! plaintext opt-out), and invitations are rejected unless the inviter or
//! room is explicitly allowlisted. See [`super::matrix_client`] for the
//! session lifecycle.

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
    access_token: Option<SecretString>,
    store_path: PathBuf,
    client: tokio::sync::OnceCell<Client>,
    policy: MatrixAccessPolicy,
    /// `true` by default: a room must advertise `m.room.encryption` before any
    /// inbound text reaches the pipeline or any outbound text is sent.
    require_encryption: bool,
    /// D2 — WAL writer for the `0x3B CHANNEL_GATE_REJECTED` audit on a drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

/// Matrix room/sender policy. Existing joined rooms remain backwards
/// compatible when both lists are unset (messages are accepted), but an
/// invitation always needs at least one explicit rule before NEOTH joins it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MatrixAccessPolicy {
    allowed_user_id: Option<String>,
    allowed_room_ids: Vec<String>,
}

impl MatrixAccessPolicy {
    fn new(allowed_user_id: Option<String>, allowed_room_ids_csv: Option<String>) -> Self {
        let allowed_user_id = allowed_user_id
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty());
        let mut allowed_room_ids = allowed_room_ids_csv
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        allowed_room_ids.sort();
        allowed_room_ids.dedup();
        Self {
            allowed_user_id,
            allowed_room_ids,
        }
    }

    fn has_invite_rule(&self) -> bool {
        self.allowed_user_id.is_some() || !self.allowed_room_ids.is_empty()
    }

    fn room_allowed(&self, room_id: &str) -> bool {
        self.allowed_room_ids.is_empty()
            || self
                .allowed_room_ids
                .iter()
                .any(|allowed| allowed == room_id)
    }

    fn sender_allowed(&self, sender: &str) -> bool {
        self.allowed_user_id
            .as_deref()
            .is_none_or(|allowed| allowed == sender)
    }

    /// Invitations are fail-closed: no rule means no join. When both room and
    /// sender rules exist they are conjunctive, so neither can bypass the other.
    fn permits_invite(&self, room_id: &str, inviter: &str) -> bool {
        self.has_invite_rule() && self.room_allowed(room_id) && self.sender_allowed(inviter)
    }

    /// Existing joined rooms preserve the historical open behavior when no
    /// policy exists. Configured dimensions are restrictive and conjunctive.
    fn permits_message(&self, room_id: &str, sender: &str) -> bool {
        self.room_allowed(room_id) && self.sender_allowed(sender)
    }
}

fn encryption_policy_allows(require_encryption: bool, room_is_encrypted: bool) -> bool {
    !require_encryption || room_is_encrypted
}

impl MatrixChannel {
    /// Build against a homeserver. `store_path` defaults to
    /// `~/.neoth/matrix_store/` when `None`. Construction is cheap + does no
    /// I/O — the network login happens lazily on first [`Self::client`].
    pub fn new(
        homeserver: impl Into<String>,
        user_id: impl Into<String>,
        password: Option<SecretString>,
        access_token: Option<SecretString>,
        store_path: Option<PathBuf>,
    ) -> Self {
        Self {
            homeserver: homeserver.into().trim_end_matches('/').to_string(),
            user_id: user_id.into(),
            password,
            access_token,
            store_path: store_path.unwrap_or_else(matrix_client::default_store_path),
            client: tokio::sync::OnceCell::new(),
            policy: MatrixAccessPolicy::default(),
            require_encryption: true,
            gate_writer: None,
        }
    }

    /// Bind room/sender policy, E2EE enforcement, and the audit writer.
    pub fn with_policy(
        mut self,
        allowed_user_id: Option<String>,
        allowed_room_ids_csv: Option<String>,
        require_encryption: bool,
        gate_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        self.policy = MatrixAccessPolicy::new(allowed_user_id, allowed_room_ids_csv);
        self.require_encryption = require_encryption;
        self.gate_writer = Some(gate_writer);
        self
    }

    fn validate_policy(&self) -> Result<()> {
        if let Some(user_id) = self.policy.allowed_user_id.as_deref() {
            matrix_sdk::ruma::UserId::parse(user_id)
                .with_context(|| format!("invalid matrix_allowed_user_id `{user_id}`"))?;
        }
        for room_id in &self.policy.allowed_room_ids {
            RoomId::parse(room_id)
                .with_context(|| format!("invalid matrix_allowed_room_ids entry `{room_id}`"))?;
        }
        Ok(())
    }

    async fn ensure_room_encryption(&self, room: &Room, operation: &str) -> Result<()> {
        ensure_room_encryption(room, self.require_encryption, operation).await
    }

    /// Lazily build + authenticate the shared client. On error the cell stays
    /// uninitialized, so a later call retries (rides out a transient
    /// homeserver outage at startup).
    async fn client(&self) -> Result<&Client> {
        self.validate_policy()?;
        self.client
            .get_or_try_init(|| async {
                let client =
                    matrix_client::build_client(&self.homeserver, &self.store_path).await?;
                matrix_client::login_or_restore(
                    &client,
                    &self.store_path,
                    &self.user_id,
                    self.password.as_ref().map(|p| p.expose()),
                    self.access_token.as_ref().map(|t| t.expose()),
                )
                .await?;
                Ok::<_, anyhow::Error>(client)
            })
            .await
    }
}

async fn ensure_room_encryption(
    room: &Room,
    require_encryption: bool,
    operation: &str,
) -> Result<()> {
    if !require_encryption {
        return Ok(());
    }
    let encrypted = room
        .latest_encryption_state()
        .await
        .with_context(|| {
            format!(
                "matrix {operation}: cannot verify encryption state for room {}",
                room.room_id()
            )
        })?
        .is_encrypted();
    if !encryption_policy_allows(true, encrypted) {
        anyhow::bail!(
            "matrix {operation}: room {} is plaintext while matrix_require_encryption=true",
            room.room_id()
        );
    }
    Ok(())
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
    /// invite-gate + message handlers, then run the live sync loop until the
    /// daemon aborts the spawned task at shutdown. A fatal client/auth error
    /// returns `Err` (the spawn loop logs it and does not restart-spin a
    /// broken config); the live `sync` loop itself retries transient network
    /// errors internally per matrix-sdk's default retry policy.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let client = self.client().await.context("matrix client init")?;
        info!(
            user = %self.user_id,
            homeserver = %self.homeserver,
            encryption_policy = if self.require_encryption { "required" } else { "plaintext-allowed" },
            invite_policy = if self.policy.has_invite_rule() { "allowlisted" } else { "deny-all" },
            "matrix adapter starting"
        );

        // Join only explicitly permitted invitations. Registered BEFORE the
        // initial sync so pending allowed invites are handled on first poll;
        // an absent policy is deny-all, never auto-join-open.
        let invite_policy = self.policy.clone();
        let invite_gate_writer = self.gate_writer.clone();
        let require_invite_encryption = self.require_encryption;
        client.add_event_handler(
            move |ev: StrippedRoomMemberEvent, room: Room, client: Client| {
                let invite_policy = invite_policy.clone();
                let invite_gate_writer = invite_gate_writer.clone();
                async move {
                // Only act on an invite addressed to US.
                let Some(me) = client.user_id() else {
                    return;
                };
                if ev.state_key.as_str() != me.as_str()
                    || ev.content.membership != MembershipState::Invite
                {
                    return;
                }
                let inviter = ev.sender.as_str();
                if !invite_policy.permits_invite(room.room_id().as_str(), inviter) {
                    warn!(
                        room = %room.room_id(),
                        inviter,
                        "matrix: invitation denied by room/sender allow policy"
                    );
                    super::emit_gate_rejected_reason(
                        invite_gate_writer.as_ref(),
                        inviter,
                        "matrix",
                        "invite_not_allowed",
                    )
                    .await;
                    if let Err(e) = room.leave().await {
                        warn!(room = %room.room_id(), error = %e, "matrix: failed to reject denied invitation");
                    }
                    return;
                }
                info!(room = %room.room_id(), inviter, "matrix: joining allowlisted invitation");
                // Retry with backoff — the inviting server can lag behind the
                // invite event.
                let mut delay_secs = 2u64;
                loop {
                    match room.join().await {
                        Ok(()) => break,
                        Err(e) => {
                            warn!(room = %room.room_id(), error = %e, "matrix: join failed; retrying");
                            if delay_secs > 60 {
                                error!(room = %room.room_id(), "matrix: giving up allowlisted join after retries");
                                return;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                            delay_secs *= 2;
                        }
                    }
                }
                if let Err(e) = ensure_room_encryption(
                    &room,
                    require_invite_encryption,
                    "post-invite join",
                )
                .await
                {
                    error!(room = %room.room_id(), error = %e, "matrix: leaving room that violates encryption policy");
                    super::emit_gate_rejected_reason(
                        invite_gate_writer.as_ref(),
                        inviter,
                        "matrix",
                        "unencrypted_room",
                    )
                    .await;
                    if let Err(leave_error) = room.leave().await {
                        warn!(room = %room.room_id(), error = %leave_error, "matrix: failed to leave policy-violating room");
                    }
                }
            }
            },
        );

        // Drain the backlog WITHOUT the message handler so a first-ever start
        // (empty store) does not reply to historical messages. With a
        // persisted store the sync token resumes, so this is cheap on later
        // starts. The invite gate IS active here, so startup invites are
        // either allowlisted-and-joined or rejected during this initial sync.
        client
            .sync_once(matrix_client::sync_settings())
            .await
            .context("matrix initial sync")?;

        // Register the message handler and run the live sync loop. The
        // pipeline handler is shared into the per-event closure via `Arc`
        // (matrix-sdk clones the handler per event; `PipelineHandler` itself
        // is not `Clone`).
        let handler = Arc::new(handler);
        // D2 — capture the operator allowlist + audit writer into the per-event
        // closure (matrix-sdk clones the closure per event, so these must be
        // owned/Clone like `handler`).
        let message_policy = self.policy.clone();
        let require_message_encryption = self.require_encryption;
        let gate_writer = self.gate_writer.clone();
        client.add_event_handler(
            move |ev: OriginalSyncRoomMessageEvent, room: Room, client: Client| {
                let handler = handler.clone();
                let message_policy = message_policy.clone();
                let gate_writer = gate_writer.clone();
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
                    // Room and sender restrictions are conjunctive. Audit the
                    // native sender before inspecting message text.
                    if !message_policy
                        .permits_message(room.room_id().as_str(), ev.sender.as_str())
                    {
                        warn!(
                            room = %room.room_id(),
                            sender = %ev.sender,
                            "matrix: inbound denied by room/sender allow policy"
                        );
                        super::emit_gate_rejected_reason(
                            gate_writer.as_ref(),
                            ev.sender.as_str(),
                            "matrix",
                            "room_or_sender_not_allowed",
                        )
                        .await;
                        return;
                    }
                    if let Err(e) = ensure_room_encryption(
                        &room,
                        require_message_encryption,
                        "inbound",
                    )
                    .await
                    {
                        warn!(room = %room.room_id(), error = %e, "matrix: inbound dropped by encryption policy");
                        super::emit_gate_rejected_reason(
                            gate_writer.as_ref(),
                            ev.sender.as_str(),
                            "matrix",
                            "unencrypted_room",
                        )
                        .await;
                        return;
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
                            // Re-check immediately before the actual write. The
                            // inbound gate above protects the pipeline; this
                            // second boundary makes the outbound guarantee
                            // explicit even if room state changed meanwhile.
                            if let Err(e) = ensure_room_encryption(
                                &room,
                                require_message_encryption,
                                "reply outbound",
                            )
                            .await
                            {
                                warn!(room = %room.room_id(), error = %e, "matrix: reply dropped by encryption policy");
                                super::emit_gate_rejected_reason(
                                    gate_writer.as_ref(),
                                    ev.sender.as_str(),
                                    "matrix",
                                    "unencrypted_room",
                                )
                                .await;
                                return;
                            }
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
        let room_id = RoomId::parse(chat_id).map_err(|e| {
            ChannelError::Transport(format!("invalid matrix room id {chat_id}: {e}"))
        })?;
        if !self.policy.room_allowed(chat_id) {
            return Err(ChannelError::Transport(format!(
                "matrix room {chat_id} is not on matrix_allowed_room_ids"
            )));
        }
        // Reject an out-of-policy destination before login/network work.
        let client = self
            .client()
            .await
            .map_err(|e| ChannelError::Auth(e.to_string()))?;
        let room = client.get_room(&room_id).ok_or_else(|| {
            ChannelError::Transport(format!("not joined to matrix room {chat_id}"))
        })?;
        self.ensure_room_encryption(&room, "outbound")
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))?;
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
        let a = MatrixChannel::new("https://matrix.org", "@bot:matrix.org", None, None, None);
        assert_eq!(a.name(), "matrix");
    }

    #[test]
    fn new_trims_trailing_slash_from_homeserver() {
        let a = MatrixChannel::new("https://matrix.org/", "@bot:matrix.org", None, None, None);
        assert_eq!(
            a.homeserver, "https://matrix.org",
            "trailing slash stripped"
        );
    }

    #[test]
    fn new_defaults_store_path_when_none() {
        let a = MatrixChannel::new("https://m.org", "@b:m.org", None, None, None);
        assert_eq!(
            a.store_path.file_name().and_then(|s| s.to_str()),
            Some("matrix_store")
        );
    }

    #[test]
    fn new_honours_explicit_store_path() {
        let custom = PathBuf::from("/tmp/neoth-matrix-test-store");
        let a = MatrixChannel::new(
            "https://m.org",
            "@b:m.org",
            None,
            None,
            Some(custom.clone()),
        );
        assert_eq!(a.store_path, custom);
    }

    #[test]
    fn configured_access_token_is_retained_for_runtime_auth() {
        let a = MatrixChannel::new(
            "https://m.org",
            "@b:m.org",
            Some(SecretString::from("password-fallback")),
            Some(SecretString::from("syt_runtime_token")),
            None,
        );
        assert_eq!(
            a.access_token.as_ref().map(|token| token.expose()),
            Some("syt_runtime_token")
        );
        assert_eq!(
            a.password.as_ref().map(|password| password.expose()),
            Some("password-fallback")
        );
    }

    #[test]
    fn invite_policy_denies_open_and_allows_only_configured_dimensions() {
        let deny_all = MatrixAccessPolicy::default();
        assert!(!deny_all.permits_invite("!safe:example.org", "@alice:example.org"));

        let sender_only = MatrixAccessPolicy::new(Some("@alice:example.org".into()), None);
        assert!(sender_only.permits_invite("!any:example.org", "@alice:example.org"));
        assert!(!sender_only.permits_invite("!any:example.org", "@mallory:example.org"));

        let room_only = MatrixAccessPolicy::new(
            None,
            Some("!safe:example.org,!ops:example.org,!safe:example.org".into()),
        );
        assert!(room_only.permits_invite("!safe:example.org", "@any:example.org"));
        assert!(!room_only.permits_invite("!other:example.org", "@any:example.org"));
        assert_eq!(room_only.allowed_room_ids.len(), 2, "CSV is deduplicated");

        let both = MatrixAccessPolicy::new(
            Some("@alice:example.org".into()),
            Some("!safe:example.org".into()),
        );
        assert!(both.permits_invite("!safe:example.org", "@alice:example.org"));
        assert!(!both.permits_invite("!safe:example.org", "@mallory:example.org"));
        assert!(!both.permits_invite("!other:example.org", "@alice:example.org"));
    }

    #[test]
    fn message_policy_preserves_open_joined_rooms_but_honours_configured_rules() {
        assert!(
            MatrixAccessPolicy::default()
                .permits_message("!existing:example.org", "@alice:example.org")
        );
        let policy = MatrixAccessPolicy::new(
            Some("@alice:example.org".into()),
            Some("!safe:example.org".into()),
        );
        assert!(policy.permits_message("!safe:example.org", "@alice:example.org"));
        assert!(!policy.permits_message("!safe:example.org", "@mallory:example.org"));
        assert!(!policy.permits_message("!other:example.org", "@alice:example.org"));
    }

    #[test]
    fn encryption_policy_is_fail_closed_unless_explicitly_disabled() {
        assert!(encryption_policy_allows(true, true));
        assert!(!encryption_policy_allows(true, false));
        assert!(encryption_policy_allows(false, true));
        assert!(
            encryption_policy_allows(false, false),
            "plaintext requires the explicit matrix_require_encryption=false opt-out"
        );
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
