//! Durable proactive queue consumer and live-channel router.
//!
//! Every terminal path (live delivery, policy suppression, local inbox, or
//! crash recovery) goes through `proactive_egress`: private Prepared claim,
//! ACKed WAL intent, private Armed transition plus ACKed Armed proof before
//! transport, terminal WAL result, and idempotent sidecar/Cron/queue
//! projections. The local JSONL inbox is an atomic, rotated operator view; it
//! is not transport authority.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{FreedomConfig, credentials::Credentials};
#[cfg(test)]
use crate::permissions::AutonomyLevel;
use crate::permissions::{Action, evaluate};
use crate::proactive::MAX_PROACTIVE_CHANNEL_BYTES;
use crate::wal::writer::WalWriterHandle;

/// Default drain-tick interval — 5 minutes in seconds. Producers
/// (G-01-mini reflection cron at 24h) enqueue at much lower
/// frequency, so 5min is comfortable: at most 12 drain ticks per
/// hour, well under the queue's daily-budget cap (default 3/day).
/// Operators tune via `freedom.yaml::proactive.drain_interval_secs`
/// in the follow-on slice.
pub const PROACTIVE_DRAIN_INTERVAL_SECS: u64 = 5 * 60;

/// Per-tick drain cap — at most N items pop per tick. Caps the
/// notification storm a bursty producer could otherwise trigger.
/// The queue's own daily budget (default 3/day) is the harder
/// guarantee; this tick-cap is just a smoothing layer.
pub const PROACTIVE_PER_TICK_CAP: usize = 3;

/// Private, rotated operator-history filename inside `~/.neoth/`. It is an
/// idempotent CLI/GUI projection of terminal WAL truth, never transport input or
/// delivery authority.
pub const PROACTIVE_DELIVERED_SIDECAR: &str = "proactive_delivered.jsonl";

pub use crate::daemon::proactive_egress::PROACTIVE_INFLIGHT_DIR;

const LOCAL_INBOX_CHANNEL: &str = "local_inbox";

/// G-01 channel-delivery (Session 28d, 4-lens gremium) — the outcome of
/// attempting to deliver ONE drained proactive item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProactiveStatus {
    /// Live-sent to the operator's channel via `Channel::send_proactive`.
    Delivered,
    /// A live send was attempted but the channel transport failed
    /// (network / bad token / rate-limit). The item is NOT re-enqueued —
    /// re-queue would starve the daily budget; the operator sees the
    /// `failed` status in the ledger + WAL and can act.
    Failed,
    /// The autonomy gate (`Action::ProactiveChannelSend`) did not return
    /// `Allow` — Strict denies, Standard confirms (no daemon TTY ⇒
    /// suppressed). No live send; ledger-only.
    Suppressed,
    /// `proactive.enabled` + autonomy permitted a send, but the item's
    /// target channel has no live adapter configured (e.g. Telegram token
    /// or recipient id absent, or a channel family delivery isn't wired
    /// yet). The JSONL ledger IS the delivery for these — zero-channel
    /// operators still see their proactive items via `proactive_delivered.jsonl`.
    SidecarOnly,
}

impl ProactiveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProactiveStatus::Delivered => "delivered",
            ProactiveStatus::Failed => "failed",
            ProactiveStatus::Suppressed => "suppressed",
            ProactiveStatus::SidecarOnly => "sidecar_only",
        }
    }

    /// True when a live channel send was attempted + succeeded — used for
    /// the loop's delivered-count log.
    pub fn is_delivered(self) -> bool {
        matches!(self, ProactiveStatus::Delivered)
    }
}

/// G-01 — the resolved route for one proactive item. Pure (no secrets, no
/// IO) so the gate + recipient-resolution decision is unit-testable in
/// isolation; the async tick consumes this to do the actual send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryRoute {
    /// Autonomy gate not `Allow` — suppress (no send).
    Suppressed,
    /// Gate allowed but no live adapter for this channel/config — ledger only.
    SidecarOnly,
    /// Deliver to Telegram. `chat_id` is the operator's OWN configured id
    /// (`telegram_user_id`) rendered as a decimal string — never a value
    /// the proactive item could influence (items carry no chat id), so the
    /// "attacker-chosen recipient" vector is structurally absent.
    Telegram { chat_id: String },
    /// GOLD-FEAT-13 — deliver to Slack. `channel_id` is the operator's OWN
    /// configured routing destination (`ChannelRouting.destinations.slack_channel_id`),
    /// never item-influenced — same anti-spoof invariant as Telegram.
    Slack { channel_id: String },
    /// GOLD-FEAT-13 — deliver to Discord. `channel_id` = operator's configured
    /// `discord_channel_id` routing destination.
    Discord { channel_id: String },
    /// GOLD-FEAT-13 — deliver to WhatsApp Cloud. `recipient` = operator's
    /// configured `whatsapp_recipient` (E.164), never item-influenced.
    WhatsApp { recipient: String },
    /// Deliver through the operator-hosted Baileys sidecar. This variant is
    /// intentionally distinct from Meta Cloud and never consumes Meta creds.
    WhatsAppBaileys { recipient: String },
    /// Deliver through the authenticated repository-owned Keet companion.
    /// The capability-secret destination stays in `Credentials` and is never
    /// copied into this Debug-visible routing enum.
    Keet,
    /// B9 — deliver via signal-cli. `recipient` = operator's configured
    /// `signal_recipient` routing destination, never item-influenced.
    Signal { recipient: String },
    /// B9 — deliver via LINE push API. `recipient` = operator's configured
    /// `line_recipient` (userId/groupId), never item-influenced.
    Line { recipient: String },
    /// B9 — deliver via Mattermost REST. `channel_id` = operator's configured
    /// `mattermost_channel_id`, never item-influenced.
    Mattermost { channel_id: String },
    /// B9 — deliver via BlueBubbles (iMessage). `chat_guid` = operator's
    /// configured `imessage_chat_guid`, never item-influenced.
    IMessage { chat_guid: String },
    /// Matrix is feature-gated but does not require the receive loop: the
    /// adapter restores its persistent device/session lazily and sends to the
    /// operator-configured room. Room policy and E2EE are re-applied at send.
    #[cfg(feature = "matrix-channel")]
    Matrix { room_id: String },
}

/// G-01 / GOLD-FEAT-13 — decide how (and whether) to deliver an item whose
/// target is `channel`, given the operator's autonomy level + config +
/// routing destinations + credentials. Two gates: (1) the autonomy
/// `Action::ProactiveChannelSend` gate, (2) live-adapter availability
/// (token present AND a configured destination). The `proactive.enabled`
/// master switch is checked by the caller BEFORE this.
///
/// Recipient/destination is ALWAYS the operator's OWN configured value
/// (`telegram_user_id` or a `ChannelRouting.destinations.*`), NEVER a value
/// the proactive item could influence — the anti-spoof invariant holds for
/// every channel. A channel with no token or no configured destination →
/// `SidecarOnly` (the operator still sees it in the ledger). Wired:
/// Telegram/Slack/Discord/WhatsApp + B9 Signal/LINE/Mattermost/iMessage and,
/// when compiled, Matrix. Matrix restores its persistent SDK session lazily;
/// remaining connection-bound adapters (IRC/Twitch/Nostr/GoogleChat) stay
/// `SidecarOnly` until their live adapter is shared with the tick. Keet is
/// constructible on demand through its authenticated local companion.
pub(crate) fn plan_delivery(
    channel: &str,
    policy: impl crate::permissions::PolicyArgument,
    config: &FreedomConfig,
    routing: &crate::channels::routing::ChannelRouting,
    credentials: &crate::config::credentials::Credentials,
) -> DeliveryRoute {
    let action = Action::ProactiveChannelSend {
        channel: channel.to_string(),
    };
    if !evaluate(&action, policy).is_allow() {
        return DeliveryRoute::Suppressed;
    }
    let dest = routing.destinations.for_channel(channel);
    match channel {
        "telegram" => match (&config.telegram_token, config.telegram_user_id) {
            (Some(_token), Some(uid)) => DeliveryRoute::Telegram {
                chat_id: uid.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        "slack" => match (
            credentials.slack_bot_token.as_ref(),
            credentials.slack_app_token.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(channel_id)) => DeliveryRoute::Slack {
                channel_id: channel_id.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        "discord" => match (credentials.discord_bot_token.as_ref(), dest) {
            (Some(_), Some(channel_id)) => DeliveryRoute::Discord {
                channel_id: channel_id.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        "whatsapp" | "whatsapp_business" => match (
            credentials.whatsapp_token.as_ref(),
            credentials.whatsapp_phone_id.as_ref(),
            credentials.whatsapp_verify_token.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(_), Some(recipient)) => DeliveryRoute::WhatsApp {
                recipient: recipient.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        "whatsapp_baileys" => match (
            credentials.whatsapp_baileys_url.as_ref(),
            credentials.whatsapp_baileys_token.as_ref(),
            credentials.whatsapp_baileys_allowed_senders.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(senders), Some(recipient)) if !senders.trim().is_empty() => {
                DeliveryRoute::WhatsAppBaileys {
                    recipient: recipient.to_string(),
                }
            }
            _ => DeliveryRoute::SidecarOnly,
        },
        // B9 — Signal via signal-cli REST: needs the daemon URL + own number
        // + a configured destination. The adapter is a stateless HTTP client,
        // constructible on demand at the send site.
        "signal" => match (
            credentials.signal_cli_url.as_ref(),
            credentials.signal_phone_number.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(recipient)) => DeliveryRoute::Signal {
                recipient: recipient.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        // B9 — LINE push REST: token + configured destination.
        "line" => match (credentials.line_channel_access_token.as_ref(), dest) {
            (Some(_), Some(recipient)) => DeliveryRoute::Line {
                recipient: recipient.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        // B9 — Mattermost REST: url + token + configured destination.
        "mattermost" => match (
            credentials.mattermost_url.as_ref(),
            credentials.mattermost_token.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(channel_id)) => DeliveryRoute::Mattermost {
                channel_id: channel_id.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        // B9 — iMessage via BlueBubbles REST: url + password + chat GUID.
        "imessage" | "imessage_bluebubbles" => match (
            credentials.bluebubbles_url.as_ref(),
            credentials.bluebubbles_password.as_ref(),
            dest,
        ) {
            (Some(_), Some(_), Some(chat_guid)) => DeliveryRoute::IMessage {
                chat_guid: chat_guid.to_string(),
            },
            _ => DeliveryRoute::SidecarOnly,
        },
        #[cfg(feature = "matrix-channel")]
        "matrix" => {
            let homeserver = credentials
                .matrix_homeserver
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            let user_id = credentials
                .matrix_user_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            let auth = credentials
                .matrix_password
                .as_ref()
                .is_some_and(|value| !value.expose().trim().is_empty())
                || credentials
                    .matrix_access_token
                    .as_ref()
                    .is_some_and(|value| !value.expose().trim().is_empty());
            match (homeserver, user_id, auth, dest) {
                (true, true, true, Some(room_id))
                    if crate::channels::routing::is_valid_matrix_room_id(room_id) =>
                {
                    DeliveryRoute::Matrix {
                        room_id: room_id.to_string(),
                    }
                }
                _ => DeliveryRoute::SidecarOnly,
            }
        }
        #[cfg(not(feature = "matrix-channel"))]
        "matrix" => DeliveryRoute::SidecarOnly,
        "keet" => {
            let complete = credentials
                .keet_bridge_url
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                && credentials
                    .keet_bridge_bearer_token
                    .as_ref()
                    .is_some_and(|value| !value.expose().trim().is_empty())
                && credentials
                    .keet_topic
                    .as_ref()
                    .is_some_and(|value| !value.expose().trim().is_empty())
                && credentials
                    .keet_allowed_senders
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty());
            let canonical_topic = credentials.keet_topic.as_ref().is_some_and(|topic| {
                crate::channels::keet_bridge::validate_topic(topic.expose()).is_ok()
            });
            if complete && canonical_topic {
                DeliveryRoute::Keet
            } else {
                DeliveryRoute::SidecarOnly
            }
        }
        // B9 — remaining connection-bound adapters (live socket / relay pool):
        // the tick can't construct them on demand, so routing destinations are
        // stored but delivery stays ledger-only until the daemon adapter is shared.
        // gchat additionally sits behind the `gchat-channel` cargo feature,
        // which this always-compiled tick can't assume.
        "irc" | "twitch" | "nostr" | "gchat" | "google_chat" => DeliveryRoute::SidecarOnly,
        _ => DeliveryRoute::SidecarOnly,
    }
}

#[derive(Debug)]
enum LiveRouteError {
    /// Item-specific adapter configuration rejected before a claim existed.
    AdapterConfiguration(String),
    /// Durable claim/WAL/projection failure. The whole tick must stop.
    Durability(String),
}

/// Construct one configured adapter and route it through the sole durable
/// proactive transport seam. Constructor failures happen before a Prepared
/// claim exists.
async fn deliver_live_route(
    egress: &crate::daemon::proactive_egress::ProactiveEgressContext<'_>,
    credentials: &Credentials,
    config: &FreedomConfig,
    item: crate::proactive::ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    route: DeliveryRoute,
) -> Result<Option<ProactiveStatus>, LiveRouteError> {
    let home = egress.home();
    let wal_segment_path = egress.wal_segment_path();
    let writer = egress.writer();
    let now_unix = egress.now_unix();
    macro_rules! execute {
        ($recipient:expr, $channel:expr) => {
            crate::daemon::proactive_egress::execute_claimed_once(
                egress,
                item,
                queue_generation,
                target_channel,
                $recipient,
                $channel,
            )
            .await
            .map_err(LiveRouteError::Durability)
        };
    }

    match route {
        DeliveryRoute::Suppressed => {
            crate::daemon::proactive_egress::record_policy_suppressed_once(
                home,
                wal_segment_path,
                writer,
                item,
                queue_generation,
                target_channel,
                now_unix,
            )
            .await
            .map_err(LiveRouteError::Durability)
        }
        DeliveryRoute::SidecarOnly => crate::daemon::proactive_egress::record_sidecar_only_once(
            home,
            wal_segment_path,
            writer,
            item,
            queue_generation,
            target_channel,
            now_unix,
        )
        .await
        .map_err(LiveRouteError::Durability),
        DeliveryRoute::Telegram { chat_id } => {
            let token = config.telegram_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Telegram proactive route lost its token".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::telegram::TelegramChannel::new(token, config.telegram_user_id),
            );
            execute!(&chat_id, channel)
        }
        DeliveryRoute::Slack { channel_id } => {
            let bot = credentials.slack_bot_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Slack proactive route lost its bot token".to_string(),
                )
            })?;
            let app = credentials.slack_app_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Slack proactive route lost its app token".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> =
                Arc::new(crate::channels::slack::SlackChannel::new(bot, app));
            execute!(&channel_id, channel)
        }
        DeliveryRoute::Discord { channel_id } => {
            let token = credentials.discord_bot_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Discord proactive route lost its token".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::discord::DiscordChannel::new(token).map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct Discord proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(&channel_id, channel)
        }
        DeliveryRoute::WhatsApp { recipient } => {
            let access = credentials.whatsapp_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "WhatsApp proactive route lost its token".to_string(),
                )
            })?;
            let phone_id = credentials.whatsapp_phone_id.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "WhatsApp proactive route lost its phone id".to_string(),
                )
            })?;
            let verify = credentials.whatsapp_verify_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "WhatsApp proactive route lost its verify token".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::whatsapp::WhatsAppChannel::new(access, phone_id, verify),
            );
            execute!(&recipient, channel)
        }
        DeliveryRoute::WhatsAppBaileys { recipient } => {
            let url = credentials.whatsapp_baileys_url.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Baileys proactive route lost its URL".to_string(),
                )
            })?;
            let token = credentials.whatsapp_baileys_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Baileys proactive route lost its token".to_string(),
                )
            })?;
            let senders = credentials
                .whatsapp_baileys_allowed_senders
                .clone()
                .ok_or_else(|| {
                    LiveRouteError::AdapterConfiguration(
                        "Baileys proactive route lost its sender policy".to_string(),
                    )
                })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::whatsapp_baileys::WhatsAppBaileysChannel::new(
                    url,
                    token,
                    senders,
                    credentials.whatsapp_baileys_allowed_groups.as_deref(),
                    home.join("channel-state/whatsapp-baileys-cursor.json"),
                )
                .map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct Baileys proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(&recipient, channel)
        }
        DeliveryRoute::Keet => {
            let url = credentials.keet_bridge_url.as_deref().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Keet proactive route lost its bridge URL".to_string(),
                )
            })?;
            let token = credentials
                .keet_bridge_bearer_token
                .clone()
                .ok_or_else(|| {
                    LiveRouteError::AdapterConfiguration(
                        "Keet proactive route lost its bearer token".to_string(),
                    )
                })?;
            let topic = credentials.keet_topic.as_ref().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Keet proactive route lost its topic".to_string(),
                )
            })?;
            let topic_capability = topic.expose();
            let allowed_senders = credentials.keet_allowed_senders.as_deref().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Keet proactive route lost its sender policy".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::keet::KeetChannel::new(
                    url,
                    token,
                    topic_capability,
                    allowed_senders,
                    home.join(crate::channels::keet::DEFAULT_CURSOR_FILE),
                )
                .map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct Keet proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(topic_capability, channel)
        }
        DeliveryRoute::Signal { recipient } => {
            let url = credentials.signal_cli_url.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Signal proactive route lost its CLI URL".to_string(),
                )
            })?;
            let number = credentials.signal_phone_number.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Signal proactive route lost its phone number".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::signal::SignalChannel::new(url, number).map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct Signal proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(&recipient, channel)
        }
        DeliveryRoute::Line { recipient } => {
            let token = credentials
                .line_channel_access_token
                .clone()
                .ok_or_else(|| {
                    LiveRouteError::AdapterConfiguration(
                        "LINE proactive route lost its access token".to_string(),
                    )
                })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::line::LineChannel::new(token).map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct LINE proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(&recipient, channel)
        }
        DeliveryRoute::Mattermost { channel_id } => {
            let url = credentials.mattermost_url.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Mattermost proactive route lost its URL".to_string(),
                )
            })?;
            let token = credentials.mattermost_token.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Mattermost proactive route lost its token".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> =
                Arc::new(crate::channels::mattermost::MattermostChannel::new(url, token));
            execute!(&channel_id, channel)
        }
        DeliveryRoute::IMessage { chat_guid } => {
            let url = credentials.bluebubbles_url.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "BlueBubbles proactive route lost its URL".to_string(),
                )
            })?;
            let password = credentials.bluebubbles_password.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "BlueBubbles proactive route lost its password".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::imessage_bluebubbles::BlueBubblesChannel::new(
                    url, password, None, None,
                )
                .map_err(|_| {
                    LiveRouteError::AdapterConfiguration(
                        "construct BlueBubbles proactive adapter: rejected".to_string(),
                    )
                })?,
            );
            execute!(&chat_guid, channel)
        }
        #[cfg(feature = "matrix-channel")]
        DeliveryRoute::Matrix { room_id } => {
            let homeserver = credentials.matrix_homeserver.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Matrix proactive route lost its homeserver".to_string(),
                )
            })?;
            let user_id = credentials.matrix_user_id.clone().ok_or_else(|| {
                LiveRouteError::AdapterConfiguration(
                    "Matrix proactive route lost its user id".to_string(),
                )
            })?;
            let channel: Arc<dyn crate::channels::Channel> = Arc::new(
                crate::channels::matrix::MatrixChannel::new(
                    homeserver,
                    user_id,
                    credentials.matrix_password.clone(),
                    credentials.matrix_access_token.clone(),
                    credentials
                        .matrix_store_path
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                        .map(PathBuf::from),
                )
                .with_policy(
                    credentials.matrix_allowed_user_id.clone(),
                    credentials.matrix_allowed_room_ids.clone(),
                    credentials.matrix_requires_encryption(),
                    writer.clone(),
                ),
            );
            execute!(&room_id, channel)
        }
    }
}

fn canonical_target_channel(resolved: Option<String>, item_channel: &str) -> Result<String, usize> {
    let channel = resolved
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let item = item_channel.trim();
            (!item.is_empty()).then_some(item)
        })
        .unwrap_or(LOCAL_INBOX_CHANNEL)
        .to_string();
    if channel.len() > MAX_PROACTIVE_CHANNEL_BYTES {
        return Err(channel.len());
    }
    Ok(channel)
}

/// Disabled proactivity still projects due items into the private operator
/// inbox through the exact same WAL/claim authority chain. It performs no
/// external transport and never uses the superseded raw JSONL writer.
async fn run_proactive_sidecar_tick(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    now_unix: i64,
) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    crate::daemon::proactive_egress::recover_pending_claims(
        home,
        wal_segment_path,
        writer,
        now_unix,
    )
    .await?;
    let queue_path = home.join("proactive_queue.json");
    let drained = tokio::task::spawn_blocking(move || {
        if !queue_path.exists() {
            return Ok(Vec::new());
        }
        ProactiveQueue::modify(&queue_path, |queue| {
            let pruned = queue.prune_expired(now_unix);
            (pruned > 0, ())
        })?;
        let mut snapshot = ProactiveQueue::load_from(&queue_path)?;
        Ok::<_, anyhow::Error>(snapshot.drain_with_generations(now_unix, PROACTIVE_PER_TICK_CAP))
    })
    .await
    .map_err(|error| format!("join disabled proactive queue selection: {error}"))?
    .map_err(|error| format!("select disabled proactive queue: {error:#}"))?;
    let mut projected = 0usize;
    for (item, queue_generation) in drained {
        let target_channel = canonical_target_channel(None, &item.channel).map_err(|bytes| {
            format!("validated proactive item produced an oversized {bytes}-byte target channel")
        })?;
        if crate::daemon::proactive_egress::record_sidecar_only_once(
            home,
            wal_segment_path,
            writer,
            item,
            &queue_generation,
            &target_channel,
            now_unix,
        )
        .await?
        .is_some()
        {
            projected += 1;
        }
    }
    Ok(projected)
}

/// Drain eligible queue items and route all live adapters through the durable
/// Prepared -> Intent -> Armed -> transport -> Result egress transaction.
pub async fn run_proactive_delivery_tick(
    home: &Path,
    wal_segment_path: &Path,
    config: &FreedomConfig,
    credentials: &Credentials,
    writer: &WalWriterHandle,
    now_unix: i64,
) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    // Recovery is deliberately first. No malformed config, disabled switch,
    // quiet-hours, idle policy or routing failure may strand an Armed claim.
    crate::daemon::proactive_egress::recover_pending_claims(
        home,
        wal_segment_path,
        writer,
        now_unix,
    )
    .await?;

    if !config.proactive.enabled {
        return Ok(0);
    }

    if let Some([start, end]) = config.proactive.quiet_hours_utc {
        let utc_hour = ((now_unix % 86_400) / 3600) as u8;
        let suppressed = if start <= end {
            utc_hour >= start && utc_hour < end
        } else {
            utc_hour >= start || utc_hour < end
        };
        if suppressed {
            return Ok(0);
        }
    }

    if config.proactive.idle_only {
        let views_db = home.join("views.db");
        match tokio::fs::try_exists(&views_db).await {
            Ok(true) => {}
            Ok(false) | Err(_) => return Ok(0),
        }
        let window_i64 = i64::try_from(config.proactive.idle_only_window_secs).unwrap_or(i64::MAX);
        let cutoff_ns = now_unix
            .saturating_sub(window_i64)
            .saturating_mul(1_000_000_000);
        let activity = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let conn = rusqlite::Connection::open_with_flags(
                &views_db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|error| format!("open activity database: {error}"))?;
            let last_ns: Option<i64> = conn
                .query_row(
                    "SELECT MAX(ts_ns) FROM idx_episode WHERE event_type = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| format!("query last operator activity: {error}"))?;
            Ok(last_ns.is_some_and(|timestamp| timestamp > cutoff_ns))
        })
        .await;
        match activity {
            Ok(Ok(false)) => {}
            Ok(Ok(true)) | Ok(Err(_)) | Err(_) => return Ok(0),
        }
    }

    let queue_path = home.join("proactive_queue.json");
    let routing_path = home.join(crate::channels::routing::CHANNEL_ROUTING_FILE);
    let (routing, drained) = tokio::task::spawn_blocking(move || {
        if !queue_path.exists() {
            return Ok((
                crate::channels::routing::ChannelRouting::default(),
                Vec::new(),
            ));
        }
        let routing = crate::channels::routing::ChannelRouting::load_from(&routing_path)
            .map_err(|error| anyhow::anyhow!("channel routing load failed: {error:#}"))?;
        ProactiveQueue::modify(&queue_path, |queue| {
            let pruned = queue.prune_expired(now_unix);
            (pruned > 0, ())
        })?;
        let mut snapshot = ProactiveQueue::load_from(&queue_path)?;
        let drained = snapshot.drain_with_generations(now_unix, PROACTIVE_PER_TICK_CAP);
        Ok::<_, anyhow::Error>((routing, drained))
    })
    .await
    .map_err(|error| format!("join proactive queue/routing selection: {error}"))?
    .map_err(|error| format!("select proactive queue/routing: {error:#}"))?;
    if drained.is_empty() {
        return Ok(0);
    }

    let policy = config.autonomy_policy();
    let egress = crate::daemon::proactive_egress::ProactiveEgressContext::new(
        home,
        wal_segment_path,
        writer,
        now_unix,
        Duration::from_secs(config.proactive.delivery_attempt_timeout_secs),
    );
    let mut delivered = 0usize;
    for (item, queue_generation) in drained {
        let target_channel = match canonical_target_channel(
            routing.resolve_channel(&item.source, item.is_failure),
            &item.channel,
        ) {
            Ok(channel) => channel,
            Err(channel_bytes) => {
                warn!(
                    channel_bytes,
                    dedup_key = %item.dedup_key,
                    "proactive routing selected an invalid channel; settling this item as failed"
                );
                let status =
                    crate::daemon::proactive_egress::record_adapter_configuration_error_once(
                        home,
                        wal_segment_path,
                        writer,
                        item,
                        &queue_generation,
                        LOCAL_INBOX_CHANNEL,
                        now_unix,
                    )
                    .await?;
                if let Some(status) = status {
                    delivered += usize::from(status.is_delivered());
                }
                continue;
            }
        };
        let route = if item.source == "g_01_mini" {
            DeliveryRoute::SidecarOnly
        } else {
            plan_delivery(&target_channel, &policy, config, &routing, credentials)
        };
        let item_for_configuration_failure = item.clone();
        let status = match deliver_live_route(
            &egress,
            credentials,
            config,
            item,
            &queue_generation,
            &target_channel,
            route,
        )
        .await
        {
            Ok(status) => status,
            Err(LiveRouteError::Durability(error)) => return Err(error),
            Err(LiveRouteError::AdapterConfiguration(error)) => {
                warn!(
                    channel = %target_channel,
                    dedup_key = %item_for_configuration_failure.dedup_key,
                    error = %error,
                    "proactive adapter configuration rejected; settling this item as failed"
                );
                crate::daemon::proactive_egress::record_adapter_configuration_error_once(
                    home,
                    wal_segment_path,
                    writer,
                    item_for_configuration_failure,
                    &queue_generation,
                    &target_channel,
                    now_unix,
                )
                .await?
            }
        };
        let Some(status) = status else { continue };
        delivered += usize::from(status.is_delivered());
    }
    Ok(delivered)
}

/// Spawn the daemon-side drain loop. Matches the doctor_cron /
/// reflection_cron pattern. Returns the JoinHandle the daemon's
/// shutdown path can `.abort()`.
///
/// Each tick reads `FreedomConfig` fresh so a mid-run `proactive.enabled` flip
/// or autonomy change takes effect without a daemon restart. Recovery always
/// runs first. Enabled items use the resolved live route; disabled items settle
/// through the same WAL transaction as `SidecarOnly`, visible in the private
/// CLI/GUI operator inbox without invoking external transport.
pub fn spawn_proactive_drain_loop(
    home: PathBuf,
    wal_segment_path: PathBuf,
    interval_secs: u64,
    writer: WalWriterHandle,
) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(30));
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            home = %home.display(),
            "proactive drain loop spawned (G-01 consumer + channel delivery)"
        );
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now_unix = crate::time::utc_now().timestamp();
            // Claim recovery precedes config loading and every delivery gate.
            // A malformed/disabled config must never strand an Armed effect.
            if let Err(error) = crate::daemon::proactive_egress::recover_pending_claims(
                &home,
                &wal_segment_path,
                &writer,
                now_unix,
            )
            .await
            {
                warn!(
                    error = %error,
                    "proactive tick: durable claim recovery failed; all delivery blocked"
                );
                continue;
            }
            // One strict fresh snapshot per tick — honours mid-run changes
            // without letting malformed policy masquerade as disabled defaults.
            let runtime = match crate::config::load_runtime_config_pair_from_path_or_default(
                &home.join("freedom.yaml"),
            ) {
                Ok(runtime) => runtime,
                Err(error) => {
                    warn!(
                        error = %error,
                        "proactive tick: config/credential snapshot invalid; delivery blocked fail-closed"
                    );
                    continue;
                }
            };
            let config = runtime.config;
            if config.proactive.enabled {
                match run_proactive_delivery_tick(
                    &home,
                    &wal_segment_path,
                    &config,
                    &runtime.credentials,
                    &writer,
                    now_unix,
                )
                .await
                {
                    Ok(0) => tracing::debug!("proactive delivery tick: nothing delivered"),
                    Ok(n) => info!(delivered = n, "proactive delivery tick: {n} live-sent"),
                    Err(e) => {
                        warn!(error = %e, "proactive delivery tick failed; will retry next interval")
                    }
                }
            } else {
                // Gate off — sidecar-only drain (no channel send).
                match run_proactive_sidecar_tick(&home, &wal_segment_path, &writer, now_unix).await
                {
                    Ok(0) => tracing::debug!("proactive drain tick: nothing to deliver"),
                    Ok(n) => info!(
                        delivered = n,
                        "proactive drain tick: {n} item(s) appended to sidecar (proactive disabled)",
                    ),
                    Err(e) => {
                        warn!(error = %e, "proactive drain tick failed; will retry next interval")
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proactive::{ProactiveItem, ProactiveQueue};
    use tempfile::TempDir;

    const TEST_KEET_TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_KEET_SENDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn item(key: &str, priority: i32, ts: i64) -> ProactiveItem {
        ProactiveItem {
            priority,
            dedup_key: key.to_string(),
            channel: "cli".to_string(),
            source: "test".to_string(),
            body: format!("test body {key}"),
            scheduled_for_unix: ts,
            is_failure: false,
            expires_unix: 0,
        }
    }

    #[tokio::test]
    async fn delivery_tick_invalid_routing_leaves_queue_untouched() {
        for routing_is_directory in [false, true] {
            let tmp = TempDir::new().unwrap();
            let queue_path = tmp.path().join("proactive_queue.json");
            let mut queue = ProactiveQueue::new();
            queue.enqueue(item("must-remain", 50, 0)).unwrap();
            queue.save_to(&queue_path).unwrap();
            let queue_before = std::fs::read(&queue_path).unwrap();

            let routing_path = tmp
                .path()
                .join(crate::channels::routing::CHANNEL_ROUTING_FILE);
            if routing_is_directory {
                std::fs::create_dir(&routing_path).unwrap();
            } else {
                std::fs::write(&routing_path, b"{not-json").unwrap();
            }

            let (writer, join) = crate::wal::spawn(tmp.path().join("routing-error.wal")).unwrap();
            let mut config = FreedomConfig::default();
            config.proactive.enabled = true;
            let error = run_proactive_delivery_tick(
                tmp.path(),
                &tmp.path().join("routing-error.wal"),
                &config,
                &Credentials::default(),
                &writer,
                1_700_000_000,
            )
            .await
            .unwrap_err();
            drop(writer);
            join.await.unwrap();

            assert!(
                error.contains("channel routing load failed"),
                "unexpected error: {error}"
            );
            assert_eq!(std::fs::read(&queue_path).unwrap(), queue_before);
            assert!(!tmp.path().join(PROACTIVE_DELIVERED_SIDECAR).exists());
            assert!(!tmp.path().join(PROACTIVE_INFLIGHT_DIR).exists());
        }
    }

    #[tokio::test]
    async fn disabled_delivery_tick_ignores_invalid_routing_and_preserves_queue() {
        let tmp = TempDir::new().unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("disabled-must-remain", 50, 0)).unwrap();
        queue.save_to(&queue_path).unwrap();
        let queue_before = std::fs::read(&queue_path).unwrap();
        std::fs::write(
            tmp.path()
                .join(crate::channels::routing::CHANNEL_ROUTING_FILE),
            b"{not-json",
        )
        .unwrap();

        let segment = tmp.path().join("disabled-routing-error.wal");
        let (writer, join) = crate::wal::spawn(segment.clone()).unwrap();
        let delivered = run_proactive_delivery_tick(
            tmp.path(),
            &segment,
            &FreedomConfig::default(),
            &Credentials::default(),
            &writer,
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        assert_eq!(delivered, 0);
        assert_eq!(std::fs::read(&queue_path).unwrap(), queue_before);
        assert!(!tmp.path().join(PROACTIVE_DELIVERED_SIDECAR).exists());
        assert!(!tmp.path().join(PROACTIVE_INFLIGHT_DIR).exists());
    }

    #[tokio::test]
    async fn invalid_adapter_configuration_settles_only_that_item_and_does_not_starve_tick() {
        let tmp = TempDir::new().unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut invalid = item("invalid-signal", 100, 0);
        invalid.channel = "signal".to_string();
        let mut later = item("later-local-inbox", 50, 0);
        later.source = "g_01_mini".to_string();
        let mut queue = ProactiveQueue::new();
        assert!(queue.enqueue(invalid).unwrap());
        assert!(queue.enqueue(later).unwrap());
        queue.save_to(&queue_path).unwrap();

        let mut routing = crate::channels::routing::ChannelRouting::default();
        routing.destinations.signal_recipient = Some("+15550000002".to_string());
        routing
            .save_to(
                &tmp.path()
                    .join(crate::channels::routing::CHANNEL_ROUTING_FILE),
            )
            .unwrap();
        let mut config = FreedomConfig::default();
        config.autonomy = AutonomyLevel::Full;
        config.proactive.enabled = true;
        let credentials = Credentials {
            signal_cli_url: Some("not-a-valid-url".to_string()),
            signal_phone_number: Some("+15550000001".to_string()),
            ..Default::default()
        };
        let wal_dir = tmp.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), tmp.path().to_path_buf())
                .unwrap();
        ready.wait().await.unwrap();

        assert_eq!(
            run_proactive_delivery_tick(
                tmp.path(),
                &segment,
                &config,
                &credentials,
                &writer,
                1_700_000_000,
            )
            .await
            .unwrap(),
            0
        );
        assert!(ProactiveQueue::load_from(&queue_path).unwrap().is_empty());
        let history = crate::daemon::proactive_egress::read_delivery_history(tmp.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history
                .iter()
                .find(|record| record.item().dedup_key == "invalid-signal")
                .unwrap()
                .outcome(),
            crate::daemon::proactive_egress::ProactiveEgressOutcome::AdapterConfigurationError
        );
        assert_eq!(
            history
                .iter()
                .find(|record| record.item().dedup_key == "later-local-inbox")
                .unwrap()
                .outcome(),
            crate::daemon::proactive_egress::ProactiveEgressOutcome::SidecarOnly
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_persisted_route_is_settled_without_starving_valid_successor() {
        let tmp = TempDir::new().unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut invalid_route = item("invalid-route", 100, 0);
        invalid_route.source = "oversized-route-source".to_string();
        let mut later = item("later-local-inbox", 50, 0);
        later.source = "g_01_mini".to_string();
        let mut queue = ProactiveQueue::new();
        assert!(queue.enqueue(invalid_route).unwrap());
        assert!(queue.enqueue(later).unwrap());
        queue.save_to(&queue_path).unwrap();

        let mut routing = crate::channels::routing::ChannelRouting::default();
        routing.by_source.insert(
            "oversized-route-source".to_string(),
            "x".repeat(MAX_PROACTIVE_CHANNEL_BYTES + 1),
        );
        routing
            .save_to(
                &tmp.path()
                    .join(crate::channels::routing::CHANNEL_ROUTING_FILE),
            )
            .unwrap();
        let mut config = FreedomConfig::default();
        config.autonomy = AutonomyLevel::Full;
        config.proactive.enabled = true;
        let wal_dir = tmp.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), tmp.path().to_path_buf())
                .unwrap();
        ready.wait().await.unwrap();

        assert_eq!(
            run_proactive_delivery_tick(
                tmp.path(),
                &segment,
                &config,
                &Credentials::default(),
                &writer,
                1_700_000_000,
            )
            .await
            .unwrap(),
            0
        );
        assert!(ProactiveQueue::load_from(&queue_path).unwrap().is_empty());
        let history = crate::daemon::proactive_egress::read_delivery_history(tmp.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history
                .iter()
                .find(|record| record.item().dedup_key == "invalid-route")
                .unwrap()
                .outcome(),
            crate::daemon::proactive_egress::ProactiveEgressOutcome::AdapterConfigurationError
        );
        assert_eq!(
            history
                .iter()
                .find(|record| record.item().dedup_key == "later-local-inbox")
                .unwrap()
                .outcome(),
            crate::daemon::proactive_egress::ProactiveEgressOutcome::SidecarOnly
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn invalid_persisted_front_item_is_quarantined_without_starving_valid_successor() {
        let tmp = TempDir::new().unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut invalid = item("invalid-front", 100, 0);
        invalid.body = format!(
            "invalid-front-secret-{}",
            "x".repeat(crate::proactive::MAX_PROACTIVE_BODY_BYTES)
        );
        let mut valid = item("valid-successor", 50, 0);
        valid.source = "g_01_mini".to_string();
        let raw_queue = serde_json::json!({
            "items": [invalid, valid],
            "drained_at": [],
            "config": { "max_per_day": 3 },
            "settled_egress_intents": [],
            "item_generations": {}
        });
        crate::util::atomic_write::atomic_write_private(
            &queue_path,
            &serde_json::to_vec(&raw_queue).unwrap(),
        )
        .unwrap();

        let wal_dir = tmp.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), tmp.path().to_path_buf())
                .unwrap();
        ready.wait().await.unwrap();
        let mut config = FreedomConfig::default();
        config.proactive.enabled = true;

        assert_eq!(
            run_proactive_delivery_tick(
                tmp.path(),
                &segment,
                &config,
                &Credentials::default(),
                &writer,
                1_700_000_000,
            )
            .await
            .unwrap(),
            0,
            "the valid local-inbox successor settles without a live send"
        );

        let queue = ProactiveQueue::load_from(&queue_path).unwrap();
        assert!(queue.is_empty());
        let persisted = std::fs::read_to_string(&queue_path).unwrap();
        assert!(persisted.contains("body_too_large"));
        assert!(!persisted.contains("invalid-front-secret"));
        let history = crate::daemon::proactive_egress::read_delivery_history(tmp.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].item().dedup_key, "valid-successor");
        assert_eq!(
            history[0].outcome(),
            crate::daemon::proactive_egress::ProactiveEgressOutcome::SidecarOnly
        );

        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_only_missing_activity_db_suppresses_and_preserves_queue() {
        let tmp = TempDir::new().unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut queue = ProactiveQueue::new();
        queue
            .enqueue(item("wait-for-confirmed-idle", 50, 0))
            .unwrap();
        queue.save_to(&queue_path).unwrap();
        let before = std::fs::read(&queue_path).unwrap();
        let mut config = FreedomConfig::default();
        config.proactive.enabled = true;
        config.proactive.idle_only = true;

        let (writer, join) = crate::wal::spawn(tmp.path().join("idle-missing.wal")).unwrap();
        let delivered = run_proactive_delivery_tick(
            tmp.path(),
            &tmp.path().join("idle-missing.wal"),
            &config,
            &Credentials::default(),
            &writer,
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        assert_eq!(delivered, 0);
        assert_eq!(std::fs::read(queue_path).unwrap(), before);
    }

    #[tokio::test]
    async fn idle_only_unreadable_activity_db_fails_closed() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("views.db"), b"not a sqlite database").unwrap();
        let queue_path = tmp.path().join("proactive_queue.json");
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("wait-on-db-error", 50, 0)).unwrap();
        queue.save_to(&queue_path).unwrap();
        let before = std::fs::read(&queue_path).unwrap();
        let mut config = FreedomConfig::default();
        config.proactive.enabled = true;
        config.proactive.idle_only = true;

        let (writer, join) = crate::wal::spawn(tmp.path().join("idle-corrupt.wal")).unwrap();
        let delivered = run_proactive_delivery_tick(
            tmp.path(),
            &tmp.path().join("idle-corrupt.wal"),
            &config,
            &Credentials::default(),
            &writer,
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        assert_eq!(delivered, 0);
        assert_eq!(std::fs::read(queue_path).unwrap(), before);
    }

    #[tokio::test]
    async fn idle_only_extreme_window_never_overflows() {
        let tmp = TempDir::new().unwrap();
        let conn = crate::memory::store::open(&tmp.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (1, 1, 1700000000000000000, 'active', 'active-hash')",
            [],
        )
        .unwrap();
        drop(conn);
        let mut config = FreedomConfig::default();
        config.proactive.enabled = true;
        config.proactive.idle_only = true;
        config.proactive.idle_only_window_secs = u64::MAX;
        let (writer, join) = crate::wal::spawn(tmp.path().join("idle-overflow.wal")).unwrap();

        let delivered = run_proactive_delivery_tick(
            tmp.path(),
            &tmp.path().join("idle-overflow.wal"),
            &config,
            &Credentials::default(),
            &writer,
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();
        assert_eq!(delivered, 0);
    }

    #[test]
    fn constants_canonical() {
        assert_eq!(PROACTIVE_DRAIN_INTERVAL_SECS, 5 * 60);
        assert_eq!(PROACTIVE_PER_TICK_CAP, 3);
        assert_eq!(PROACTIVE_DELIVERED_SIDECAR, "proactive_delivered.jsonl");
    }

    #[test]
    fn empty_or_blank_target_resolves_to_the_local_operator_inbox() {
        assert_eq!(
            canonical_target_channel(None, "").unwrap(),
            LOCAL_INBOX_CHANNEL
        );
        assert_eq!(
            canonical_target_channel(Some("   ".to_string()), " \t").unwrap(),
            LOCAL_INBOX_CHANNEL
        );
        assert_eq!(
            canonical_target_channel(Some("telegram".to_string()), "cli").unwrap(),
            "telegram"
        );
        assert_eq!(
            canonical_target_channel(Some("x".repeat(MAX_PROACTIVE_CHANNEL_BYTES + 1)), "cli"),
            Err(MAX_PROACTIVE_CHANNEL_BYTES + 1)
        );
    }

    // ── G-01 channel-delivery (Session 28d) ──────────────────────────────
    fn cfg_with_telegram(autonomy: AutonomyLevel) -> FreedomConfig {
        let mut c = FreedomConfig::default();
        c.autonomy = autonomy;
        c.telegram_token = Some(crate::secret::SecretString::from(
            "test-bot-token".to_string(),
        ));
        c.telegram_user_id = Some(123456);
        c
    }

    fn default_rt() -> crate::channels::routing::ChannelRouting {
        crate::channels::routing::ChannelRouting::default()
    }
    fn default_creds() -> crate::config::credentials::Credentials {
        crate::config::credentials::Credentials::default()
    }

    #[test]
    fn plan_delivery_strict_suppresses() {
        // Strict autonomy denies daemon-initiated outbound regardless of
        // channel config.
        let cfg = cfg_with_telegram(AutonomyLevel::Strict);
        assert_eq!(
            plan_delivery(
                "telegram",
                AutonomyLevel::Strict,
                &cfg,
                &default_rt(),
                &default_creds()
            ),
            DeliveryRoute::Suppressed
        );
    }

    #[test]
    fn plan_delivery_standard_suppresses() {
        // Standard ⇒ Confirm ⇒ not Allow ⇒ suppressed (no daemon TTY).
        let cfg = cfg_with_telegram(AutonomyLevel::Standard);
        assert_eq!(
            plan_delivery(
                "telegram",
                AutonomyLevel::Standard,
                &cfg,
                &default_rt(),
                &default_creds()
            ),
            DeliveryRoute::Suppressed
        );
    }

    #[test]
    fn plan_delivery_elevated_telegram_configured_routes_to_telegram() {
        let cfg = cfg_with_telegram(AutonomyLevel::Elevated);
        assert_eq!(
            plan_delivery(
                "telegram",
                AutonomyLevel::Elevated,
                &cfg,
                &default_rt(),
                &default_creds()
            ),
            DeliveryRoute::Telegram {
                chat_id: "123456".to_string()
            }
        );
    }

    #[test]
    fn plan_delivery_elevated_telegram_unconfigured_is_sidecar_only() {
        // Gate allows, but no telegram token/recipient ⇒ ledger-only.
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Elevated;
        // No telegram_token / telegram_user_id set.
        assert_eq!(
            plan_delivery(
                "telegram",
                AutonomyLevel::Elevated,
                &cfg,
                &default_rt(),
                &default_creds()
            ),
            DeliveryRoute::SidecarOnly
        );
    }

    #[test]
    fn plan_delivery_unconfigured_non_telegram_is_sidecar_only() {
        // GOLD-FEAT-13: with NO routing destination + NO credentials, every
        // non-telegram channel is ledger-only — the fallback-chain terminal.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        for ch in ["slack", "discord", "keet", "whatsapp", "cli"] {
            assert_eq!(
                plan_delivery(
                    ch,
                    AutonomyLevel::Full,
                    &cfg,
                    &default_rt(),
                    &default_creds()
                ),
                DeliveryRoute::SidecarOnly,
                "channel {ch} with no dest/token must be sidecar-only",
            );
        }
    }

    #[test]
    fn plan_delivery_routes_to_discord_when_token_and_destination_configured() {
        // GOLD-FEAT-13: a configured Discord destination + bot token → Discord
        // route. channel_id is the operator's OWN configured value.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.discord_channel_id = Some("987654321".to_string());
        let creds = crate::config::credentials::Credentials {
            discord_bot_token: Some(crate::secret::SecretString::from("bot".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("discord", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Discord {
                channel_id: "987654321".to_string()
            }
        );
    }

    #[test]
    fn plan_delivery_discord_without_destination_is_sidecar_only() {
        // Token present but NO configured destination → sidecar (never guess).
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let creds = crate::config::credentials::Credentials {
            discord_bot_token: Some(crate::secret::SecretString::from("bot".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("discord", AutonomyLevel::Full, &cfg, &default_rt(), &creds),
            DeliveryRoute::SidecarOnly
        );
    }

    #[test]
    fn plan_delivery_b9_channels_route_when_configured() {
        // B9 parity — Signal/LINE/Mattermost/iMessage route when credentials
        // + operator-own destination are present.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.signal_recipient = Some("+491701234567".to_string());
        rt.destinations.line_recipient = Some("Uab12cd34".to_string());
        rt.destinations.mattermost_channel_id = Some("chanid26".to_string());
        rt.destinations.imessage_chat_guid = Some("iMessage;-;+4917".to_string());
        let creds = crate::config::credentials::Credentials {
            signal_cli_url: Some("http://127.0.0.1:8080".to_string()),
            signal_phone_number: Some("+491700000000".to_string()),
            line_channel_access_token: Some(crate::secret::SecretString::from(
                "line-token".to_string(),
            )),
            mattermost_url: Some("https://mm.example.com".to_string()),
            mattermost_token: Some(crate::secret::SecretString::from("mm".to_string())),
            bluebubbles_url: Some("http://192.168.1.5:1234".to_string()),
            bluebubbles_password: Some(crate::secret::SecretString::from("pw".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("signal", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Signal {
                recipient: "+491701234567".to_string()
            }
        );
        assert_eq!(
            plan_delivery("line", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Line {
                recipient: "Uab12cd34".to_string()
            }
        );
        assert_eq!(
            plan_delivery("mattermost", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Mattermost {
                channel_id: "chanid26".to_string()
            }
        );
        // both alias spellings hit the same route
        for ch in ["imessage", "imessage_bluebubbles"] {
            assert_eq!(
                plan_delivery(ch, AutonomyLevel::Full, &cfg, &rt, &creds),
                DeliveryRoute::IMessage {
                    chat_guid: "iMessage;-;+4917".to_string()
                },
                "{ch} routes to IMessage"
            );
        }
    }

    #[test]
    fn plan_delivery_b9_without_destination_or_creds_is_sidecar_only() {
        // Credentials WITHOUT destination → sidecar; destination WITHOUT
        // credentials → sidecar. Never guess a recipient.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let creds_only = crate::config::credentials::Credentials {
            signal_cli_url: Some("http://127.0.0.1:8080".to_string()),
            signal_phone_number: Some("+491700000000".to_string()),
            line_channel_access_token: Some(crate::secret::SecretString::from(
                "line-token".to_string(),
            )),
            ..Default::default()
        };
        for ch in ["signal", "line", "mattermost", "imessage"] {
            assert_eq!(
                plan_delivery(ch, AutonomyLevel::Full, &cfg, &default_rt(), &creds_only),
                DeliveryRoute::SidecarOnly,
                "{ch} without destination must be sidecar-only"
            );
        }
        let mut rt = default_rt();
        rt.destinations.signal_recipient = Some("+491701234567".to_string());
        assert_eq!(
            plan_delivery("signal", AutonomyLevel::Full, &cfg, &rt, &default_creds()),
            DeliveryRoute::SidecarOnly,
            "signal destination without signal-cli credentials must be sidecar-only"
        );
    }

    #[test]
    fn plan_delivery_b9_connection_bound_channels_are_sidecar_only() {
        // IRC/Twitch/Nostr/GChat remain connection-bound — destinations are
        // stored but the tick can't construct their adapters on demand.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.irc_channel = Some("#neoth".to_string());
        rt.destinations.twitch_channel = Some("#chan".to_string());
        rt.destinations.nostr_recipient = Some("npub1x".to_string());
        rt.destinations.gchat_space = Some("spaces/AAAA".to_string());
        for ch in ["irc", "twitch", "nostr", "gchat", "google_chat"] {
            assert_eq!(
                plan_delivery(ch, AutonomyLevel::Full, &cfg, &rt, &default_creds()),
                DeliveryRoute::SidecarOnly,
                "{ch} is connection-bound → sidecar-only"
            );
        }
    }

    #[cfg(feature = "matrix-channel")]
    #[test]
    fn plan_delivery_matrix_feature_on_accepts_token_or_password_and_valid_room() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.matrix_room_id = Some("!ops:example.org".to_string());
        let token_creds = crate::config::credentials::Credentials {
            matrix_homeserver: Some("https://matrix.example.org".to_string()),
            matrix_user_id: Some("@neoth:example.org".to_string()),
            matrix_access_token: Some(crate::secret::SecretString::from("syt_token")),
            matrix_allowed_user_id: Some("@operator:example.org".to_string()),
            matrix_allowed_room_ids: Some("!ops:example.org".to_string()),
            matrix_require_encryption: Some(true),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("matrix", AutonomyLevel::Full, &cfg, &rt, &token_creds),
            DeliveryRoute::Matrix {
                room_id: "!ops:example.org".to_string()
            }
        );

        let password_creds = crate::config::credentials::Credentials {
            matrix_access_token: None,
            matrix_password: Some(crate::secret::SecretString::from("password")),
            ..token_creds
        };
        assert_eq!(
            plan_delivery("matrix", AutonomyLevel::Full, &cfg, &rt, &password_creds),
            DeliveryRoute::Matrix {
                room_id: "!ops:example.org".to_string()
            }
        );
    }

    #[cfg(feature = "matrix-channel")]
    #[test]
    fn plan_delivery_matrix_feature_on_fails_closed_for_partial_or_bad_destination() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let complete = crate::config::credentials::Credentials {
            matrix_homeserver: Some("https://matrix.example.org".to_string()),
            matrix_user_id: Some("@neoth:example.org".to_string()),
            matrix_access_token: Some(crate::secret::SecretString::from("syt_token")),
            ..Default::default()
        };
        let mut no_destination = default_rt();
        assert_eq!(
            plan_delivery(
                "matrix",
                AutonomyLevel::Full,
                &cfg,
                &no_destination,
                &complete
            ),
            DeliveryRoute::SidecarOnly
        );

        no_destination.destinations.matrix_room_id = Some("not-a-room".to_string());
        assert_eq!(
            plan_delivery(
                "matrix",
                AutonomyLevel::Full,
                &cfg,
                &no_destination,
                &complete
            ),
            DeliveryRoute::SidecarOnly
        );

        no_destination.destinations.matrix_room_id = Some("!ops:example.org".to_string());
        let missing_auth = crate::config::credentials::Credentials {
            matrix_homeserver: complete.matrix_homeserver.clone(),
            matrix_user_id: complete.matrix_user_id.clone(),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery(
                "matrix",
                AutonomyLevel::Full,
                &cfg,
                &no_destination,
                &missing_auth
            ),
            DeliveryRoute::SidecarOnly
        );
    }

    #[cfg(not(feature = "matrix-channel"))]
    #[test]
    fn plan_delivery_matrix_feature_off_stays_sidecar_only() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.matrix_room_id = Some("!ops:example.org".to_string());
        let creds = crate::config::credentials::Credentials {
            matrix_homeserver: Some("https://matrix.example.org".to_string()),
            matrix_user_id: Some("@neoth:example.org".to_string()),
            matrix_access_token: Some(crate::secret::SecretString::from("syt_token")),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("matrix", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::SidecarOnly
        );
    }

    #[test]
    fn plan_delivery_slack_needs_both_tokens_and_destination() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.slack_channel_id = Some("C0B0QV5434G".to_string());
        let creds = crate::config::credentials::Credentials {
            slack_bot_token: Some(crate::secret::SecretString::from("xoxb".to_string())),
            slack_app_token: Some(crate::secret::SecretString::from("xapp".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("slack", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Slack {
                channel_id: "C0B0QV5434G".to_string()
            }
        );
        // Missing the app token → sidecar (SlackChannel::new needs both).
        let creds_bot_only = crate::config::credentials::Credentials {
            slack_bot_token: Some(crate::secret::SecretString::from("xoxb".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("slack", AutonomyLevel::Full, &cfg, &rt, &creds_bot_only),
            DeliveryRoute::SidecarOnly,
            "slack requires BOTH bot + app tokens"
        );
    }

    #[test]
    fn plan_delivery_routes_to_whatsapp_when_all_creds_and_dest() {
        // WhatsApp needs access_token + phone_id + verify_token (the 3-arg
        // constructor) AND a configured recipient.
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.whatsapp_recipient = Some("+15551234567".to_string());
        let creds = crate::config::credentials::Credentials {
            whatsapp_token: Some(crate::secret::SecretString::from("acc".to_string())),
            whatsapp_phone_id: Some("phone123".to_string()),
            whatsapp_verify_token: Some(crate::secret::SecretString::from("vt".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("whatsapp", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::WhatsApp {
                recipient: "+15551234567".to_string()
            }
        );
        // Missing the phone_id → can't construct → sidecar.
        let creds_no_phone = crate::config::credentials::Credentials {
            whatsapp_token: Some(crate::secret::SecretString::from("acc".to_string())),
            whatsapp_verify_token: Some(crate::secret::SecretString::from("vt".to_string())),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("whatsapp", AutonomyLevel::Full, &cfg, &rt, &creds_no_phone),
            DeliveryRoute::SidecarOnly
        );
    }

    #[test]
    fn plan_delivery_keeps_baileys_and_meta_credentials_separate() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let mut rt = default_rt();
        rt.destinations.whatsapp_recipient = Some("+15550000001".to_string());
        rt.destinations.whatsapp_baileys_recipient = Some("+15550000002".to_string());

        let meta = crate::config::credentials::Credentials {
            whatsapp_token: Some(crate::secret::SecretString::from("meta")),
            whatsapp_phone_id: Some("phone".into()),
            whatsapp_verify_token: Some(crate::secret::SecretString::from("verify")),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("whatsapp_baileys", AutonomyLevel::Full, &cfg, &rt, &meta),
            DeliveryRoute::SidecarOnly,
            "Meta credentials must never activate the Baileys route"
        );

        let baileys = crate::config::credentials::Credentials {
            whatsapp_baileys_url: Some("http://127.0.0.1:9120".into()),
            whatsapp_baileys_token: Some(crate::secret::SecretString::from(
                "0123456789abcdef0123456789abcdef",
            )),
            whatsapp_baileys_allowed_senders: Some("+15550000002".into()),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("whatsapp", AutonomyLevel::Full, &cfg, &rt, &baileys),
            DeliveryRoute::SidecarOnly,
            "Baileys credentials must never activate the Meta route"
        );
        assert_eq!(
            plan_delivery("whatsapp_baileys", AutonomyLevel::Full, &cfg, &rt, &baileys,),
            DeliveryRoute::WhatsAppBaileys {
                recipient: "+15550000002".into(),
            }
        );
    }

    #[test]
    fn plan_delivery_keet_uses_only_the_secret_credential_topic() {
        let cfg = cfg_with_telegram(AutonomyLevel::Full);
        let rt = default_rt();
        let creds = crate::config::credentials::Credentials {
            keet_bridge_url: Some("http://127.0.0.1:9130".into()),
            keet_topic: Some(crate::secret::SecretString::from(TEST_KEET_TOPIC)),
            keet_allowed_senders: Some(TEST_KEET_SENDER.into()),
            keet_bridge_bearer_token: Some(crate::secret::SecretString::from(
                "0123456789abcdef0123456789abcdef",
            )),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("keet", AutonomyLevel::Full, &cfg, &rt, &creds),
            DeliveryRoute::Keet
        );
        assert!(!format!("{:?}", DeliveryRoute::Keet).contains(TEST_KEET_TOPIC));
        let partial = crate::config::credentials::Credentials {
            keet_bridge_url: Some("http://127.0.0.1:9130".into()),
            ..Default::default()
        };
        assert_eq!(
            plan_delivery("keet", AutonomyLevel::Full, &cfg, &rt, &partial),
            DeliveryRoute::SidecarOnly,
            "partial companion config must fail closed"
        );
    }

    #[test]
    fn proactive_status_as_str_pinned() {
        assert_eq!(ProactiveStatus::Delivered.as_str(), "delivered");
        assert_eq!(ProactiveStatus::Failed.as_str(), "failed");
        assert_eq!(ProactiveStatus::Suppressed.as_str(), "suppressed");
        assert_eq!(ProactiveStatus::SidecarOnly.as_str(), "sidecar_only");
        assert!(ProactiveStatus::Delivered.is_delivered());
        assert!(!ProactiveStatus::Failed.is_delivered());
    }
}
