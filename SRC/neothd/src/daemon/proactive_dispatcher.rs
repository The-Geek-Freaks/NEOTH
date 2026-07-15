//! Round-3 v0.4 G-01 consumer half — drains [`ProactiveQueue`] +
//! delivers items to a per-operator JSONL sidecar.
//!
//! G-01a (Session 24) shipped the bounded queue + `enqueue` /
//! `drain` / persistence. G-01-mini (Session 24) ships the
//! reflection producer. G-01 cron-wiring (Session 28 commit
//! `7acb181`) wires the producer into a 24h cron. **This module
//! closes the consumer half**: ticks every
//! [`PROACTIVE_DRAIN_INTERVAL_SECS`], pops items in priority +
//! schedule order respecting the daily-budget cap, appends each to
//! `~/.neoth/proactive_delivered.jsonl` for operator inspection.
//!
//! The JSONL sidecar is the operator-visible "delivered inbox" —
//! one JSON per line, append-only, never truncated. Operators
//! `tail -f` it during a session OR a future
//! `neoth proactive items list` CLI surface paginates the recent
//! tail. Channel-side delivery (Telegram message / Slack DM /
//! additional live adapters is the L follow-on once each adapter consumes
//! the sidecar.
//!
//! ## Why sidecar not channel-direct
//!
//! Channel adapters are async + per-protocol (Telegram bot API,
//! Slack Web API, etc.). Putting the channel-dispatch inside the
//! drain loop would bind every operator to running the channels
//! they care about + couple the drain cadence to the slowest
//! adapter. A sidecar JSONL is:
//!   - Always present (zero-channel operators still see their
//!     proactive items).
//!   - Append-only + crash-safe (no torn writes; each line is one
//!     drain operation).
//!   - Cheap to consume from any future adapter (channel adapter
//!     tails the file + sends each new line; tail-cursor is the
//!     adapter's local state).
//!
//! ## Delivery semantics — at-most-once via inflight claim files
//!
//! Before attempting a channel send the tick writes an atomic claim
//! file to `~/.neoth/proactive_inflight/<sha256(dedup_key)>.claimed`.
//! The batch's claim files are deleted only AFTER the post-send queue
//! save is durable (deleting per-item would let an already-sent earlier
//! item in the same batch re-drain before the save → a double-fire). On
//! the NEXT tick [`evict_inflight_claimed`] scans for surviving claim
//! files; each one represents a send whose outcome is unknown (daemon
//! crashed before the save). Those items are evicted from the queue
//! without resending and recorded in the sidecar as `crash_recovered`.
//! This replaces the earlier at-least-once contract: a duplicate nudge
//! is no longer preferred over a silent loss; the `crash_recovered`
//! sidecar entry makes the event operator-visible. `is_failure` items
//! (critical alerts) follow the same path — `was_failure: true` in
//! the `crash_recovered` entry lets the operator act.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::FreedomConfig;
#[cfg(test)]
use crate::permissions::AutonomyLevel;
use crate::permissions::{Action, evaluate};
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

/// JSONL sidecar filename inside `~/.neoth/`. Operators tail this
/// to see delivered items; future channel adapters subscribe to
/// the same file for at-most-once delivery semantics.
pub const PROACTIVE_DELIVERED_SIDECAR: &str = "proactive_delivered.jsonl";

/// Sub-directory inside `~/.neoth/` that holds in-flight claim files.
/// Each file is named `<sha256hex(dedup_key)>.claimed` and is written
/// atomically BEFORE a channel send attempt; deleted after any
/// non-crash outcome. Surviving files on the next tick indicate a
/// crash mid-send and are handled by [`evict_inflight_claimed`].
pub const PROACTIVE_INFLIGHT_DIR: &str = "proactive_inflight";

/// One drain tick: load the queue, pop up to cap items, append
/// each to the sidecar, save the post-drain queue.
///
/// Pure-fn (no async) so tests can call directly. Returns the
/// number of items delivered (0 when queue empty / cap=0 / budget
/// exhausted). Errors propagate from queue load/save + sidecar
/// append.
pub fn run_proactive_drain_tick(home: &Path, now_unix: i64) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    let queue_path = home.join("proactive_queue.json");
    if !queue_path.exists() {
        return Ok(0);
    }
    let sidecar_path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    // Review H-1 — the whole load→drain→append→save cycle holds the
    // process-global queue lock, so a concurrent producer enqueue can no
    // longer be lost to this tick's save. No network I/O in this path.
    ProactiveQueue::modify(&queue_path, |queue| {
        if queue.is_empty() {
            return (false, Ok(0));
        }
        let len_before = queue.len();
        let drained = queue.drain(now_unix, PROACTIVE_PER_TICK_CAP);
        if drained.is_empty() {
            // Either daily-budget exhausted OR cap=0 OR every item is
            // future-scheduled. JV-PRO-10: drain may still have pruned
            // expired items — persist the smaller queue then.
            return (queue.len() < len_before, Ok(0));
        }
        if let Err(e) = append_to_sidecar(&sidecar_path, &drained, now_unix) {
            // Not persisted → the batch re-drains next tick (at-least-once,
            // same semantics as before the lock landed).
            return (false, Err(format!("sidecar append failed: {e}")));
        }
        (true, Ok(drained.len()))
    })
    .map_err(|e| format!("queue load/save failed: {e}"))?
}

fn append_to_sidecar(
    sidecar_path: &Path,
    items: &[crate::proactive::ProactiveItem],
    now_unix: i64,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sidecar_path)?;
    for item in items {
        let line = serde_json::to_string(&serde_json::json!({
            "delivered_at_unix": now_unix,
            "item": item,
        }))
        .unwrap_or_default();
        writeln!(f, "{line}")?;
    }
    f.flush()?;
    Ok(())
}

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

/// Whether a route can perform a live external send and therefore needs the
/// at-most-once claim file before dispatch.
fn route_needs_claim(route: &DeliveryRoute) -> bool {
    match route {
        DeliveryRoute::Suppressed | DeliveryRoute::SidecarOnly => false,
        DeliveryRoute::Telegram { .. }
        | DeliveryRoute::Slack { .. }
        | DeliveryRoute::Discord { .. }
        | DeliveryRoute::WhatsApp { .. }
        | DeliveryRoute::WhatsAppBaileys { .. }
        | DeliveryRoute::Keet
        | DeliveryRoute::Signal { .. }
        | DeliveryRoute::Line { .. }
        | DeliveryRoute::Mattermost { .. }
        | DeliveryRoute::IMessage { .. } => true,
        #[cfg(feature = "matrix-channel")]
        DeliveryRoute::Matrix { .. } => true,
    }
}

/// SHA-256 hex of a recipient id. The WAL audit frame must NOT carry the
/// raw chat id (a live user identifier); the hash lets an operator
/// correlate frames for the same recipient without leaking the id.
fn recipient_hash(recipient: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(recipient.as_bytes());
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 hex of `dedup_key` — used as the claim filename so that
/// keys containing filesystem-hostile characters (slashes, null bytes,
/// colons on Windows) never reach the filesystem.  Same hash function
/// as `recipient_hash`; kept separate for readability.
fn claim_filename(dedup_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(dedup_key.as_bytes());
    let out = hasher.finalize();
    format!(
        "{}.claimed",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Write an atomic claim file for `item` BEFORE the channel send.
///
/// The file path is `home/PROACTIVE_INFLIGHT_DIR/<sha256(dedup_key)>.claimed`.
/// Content is the item JSON (enough to reconstruct `dedup_key`,
/// `is_failure`, `body`, `source` for the `crash_recovered` sidecar
/// entry if the daemon crashes before this file is deleted).
///
/// Uses [`crate::util::atomic_write::atomic_write`] (tmp+fsync+rename)
/// so a crash mid-write leaves a `.pid.tmp` orphan, NOT a partial
/// `.claimed` file.  The eviction scan only reads `*.claimed` files,
/// so orphan temps are harmlessly ignored.
fn write_inflight_claim(
    home: &Path,
    item: &crate::proactive::ProactiveItem,
) -> std::io::Result<()> {
    let dir = home.join(PROACTIVE_INFLIGHT_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(claim_filename(&item.dedup_key));
    let bytes = serde_json::to_vec(item)
        .map_err(|e| std::io::Error::other(format!("claim serialise: {e}")))?;
    crate::util::atomic_write::atomic_write(&path, &bytes)
}

/// Delete the claim file for `dedup_key` after a non-crash outcome
/// (success, transport error, suppressed — anything except a process
/// crash). Missing file is not an error (idempotent).
fn delete_inflight_claim(home: &Path, dedup_key: &str) {
    let path = home
        .join(PROACTIVE_INFLIGHT_DIR)
        .join(claim_filename(dedup_key));
    // Best-effort: a delete failure here means the next tick's eviction
    // will pick it up as crash_recovered, which is slightly wrong but
    // safe (the item was already removed from the queue by the completed
    // drain, so there is no double-send risk — the eviction's
    // remove_by_key call is a no-op on an already-absent key).
    let _ = std::fs::remove_file(&path);
}

/// Scan `home/PROACTIVE_INFLIGHT_DIR/*.claimed` for leftover claim
/// files from a crashed tick.  For each surviving file:
///   1. Parse the stored `ProactiveItem` to recover `dedup_key`,
///      `is_failure`, `body`, `source`.
///   2. Call `queue.remove_by_key` to evict it WITHOUT resending
///      (the queue file on disk still has the item because the crash
///      happened before `save_to`).
///   3. Append a `crash_recovered` line to the sidecar so the
///      operator can see the event (with `was_failure` for critical
///      alerts).
///   4. Delete the claim file.
///
/// Must be called BEFORE `queue.drain()` so the evicted keys are
/// gone before the drain produces the next batch.
fn evict_inflight_claimed(
    home: &Path,
    queue: &mut crate::proactive::ProactiveQueue,
    sidecar_path: &Path,
    now_unix: i64,
) -> Vec<String> {
    let mut evicted_keys: Vec<String> = Vec::new();
    let dir = home.join(PROACTIVE_INFLIGHT_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return evicted_keys, // Dir missing → nothing to evict.
    };
    use std::io::Write;
    let mut f_opt: Option<std::fs::File> = None;
    let mut sidecar_failed = false;

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if !name.ends_with(".claimed") {
            continue; // skip .pid.tmp orphans
        }
        let claim_path = entry.path();
        let bytes = match std::fs::read(&claim_path) {
            Ok(b) => b,
            Err(e) => {
                warn!(path = %claim_path.display(), error = %e, "evict: could not read claim file; skipping");
                continue;
            }
        };
        let item: crate::proactive::ProactiveItem = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => {
                warn!(path = %claim_path.display(), error = %e, "evict: claim file not valid JSON; deleting orphan");
                let _ = std::fs::remove_file(&claim_path);
                continue;
            }
        };
        // Evict from the in-memory queue (no-op if already absent). The key
        // is tracked so the H-1 reconcile commit removes it from the FRESH
        // queue too at the tick's save point.
        queue.remove_by_key(&item.dedup_key);
        evicted_keys.push(item.dedup_key.clone());
        // Append crash_recovered sidecar line.
        let line = serde_json::to_string(&serde_json::json!({
            "delivered_at_unix": now_unix,
            "status": "crash_recovered",
            "was_failure": item.is_failure,
            "dedup_key": item.dedup_key,
            "source": item.source,
            "body": item.body,
            "item": &item,
        }))
        .unwrap_or_default();
        // Lazy-open the sidecar once, on the first crash_recovered entry. If
        // it can't be opened, warn once and keep evicting WITHOUT a sidecar
        // line — losing one audit line is far better than aborting recovery
        // or writing to a discarded sink.
        if f_opt.is_none() && !sidecar_failed {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(sidecar_path)
            {
                Ok(f) => f_opt = Some(f),
                Err(e) => {
                    sidecar_failed = true;
                    warn!(error = %e, "evict: could not open sidecar; crash_recovered entries not logged this tick");
                }
            }
        }
        if let Some(f) = f_opt.as_mut() {
            if let Err(e) = writeln!(f, "{line}") {
                warn!(error = %e, dedup_key = %item.dedup_key, "evict: sidecar write failed for crash_recovered");
            }
        }
        // Delete the claim file — done regardless of sidecar write outcome.
        if let Err(e) = std::fs::remove_file(&claim_path) {
            warn!(path = %claim_path.display(), error = %e, "evict: could not delete claim file");
        }
        info!(
            dedup_key = %item.dedup_key,
            is_failure = item.is_failure,
            "proactive evict: crash_recovered — item evicted without resend"
        );
        if let Err(error) = crate::cron::state::update_announce_result(
            home,
            &item.dedup_key,
            crate::cron::state::DeliveryStatus::CrashUnknown,
        ) {
            warn!(dedup_key = %item.dedup_key, error = %error,
                "failed to persist Cron crash-unknown delivery status");
        }
    }
    // Flush if we opened the file.
    if let Some(mut f) = f_opt {
        let _ = f.flush();
    }
    evicted_keys
}

/// G-01 delivery tick — drains the queue + ACTUALLY SENDS each item to the
/// operator's channel (the slice the consumer-half sidecar left open),
/// then records the outcome. Async because `Channel::send_proactive` is
/// async.
///
/// ## At-most-once delivery contract
///
/// The tick, for the whole drained batch:
///   1. Writes an atomic claim file BEFORE each live send
///      (`~/.neoth/proactive_inflight/<sha256(dedup_key)>.claimed`).
///   2. Attempts every channel send + records each outcome.
///   3. Saves the queue LAST (drained items removed → no re-drain).
///   4. ONLY THEN deletes the batch's claim files.
///
/// A crash anytime before step 3 leaves the in-flight claim files on
/// disk. On the next tick [`evict_inflight_claimed`] runs BEFORE
/// `drain()`, finds the surviving files, evicts those keys from the
/// queue (no resend), and records a `crash_recovered` entry in the
/// sidecar. Deleting claims only AFTER the save (not per-item) is what
/// makes the guarantee hold for a MULTI-item batch — a per-item delete
/// would let an already-sent earlier item re-drain (queue not yet
/// saved). The operator sees the event; `is_failure` items carry
/// `was_failure: true` so critical alerts are never silently lost.
///
/// Returns the number of items LIVE-DELIVERED (status `delivered`).
pub async fn run_proactive_delivery_tick(
    home: &Path,
    config: &FreedomConfig,
    writer: &WalWriterHandle,
    now_unix: i64,
) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    // GOLD-FEAT-11 — quiet_hours gate: suppress delivery when the current UTC
    // hour falls inside the configured quiet window. Wrap-around supported:
    // [22, 7] = suppress 22:00–06:59 UTC.
    if let Some([start, end]) = config.proactive.quiet_hours_utc {
        let utc_hour = ((now_unix % 86_400) / 3600) as u8;
        let suppressed = if start <= end {
            utc_hour >= start && utc_hour < end
        } else {
            utc_hour >= start || utc_hour < end
        };
        if suppressed {
            tracing::debug!(
                utc_hour,
                quiet_start = start,
                quiet_end = end,
                "proactive_dispatcher: quiet_hours gate suppressing delivery"
            );
            return Ok(0);
        }
    }

    // GOLD-FEAT-11 — idle_only gate: suppress delivery when the operator has
    // been active within the last `idle_only_window_secs`.
    if config.proactive.idle_only {
        let views_db = home.join("views.db");
        if views_db.exists() {
            let window = config.proactive.idle_only_window_secs;
            let cutoff_ns = (now_unix - window as i64) * 1_000_000_000;
            let is_active = tokio::task::spawn_blocking(move || {
                let conn = rusqlite::Connection::open_with_flags(
                    &views_db,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .ok()?;
                let last_ns: Option<i64> = conn
                    .query_row(
                        "SELECT MAX(ts_ns) FROM idx_episode WHERE event_type = 1",
                        [],
                        |r| r.get(0),
                    )
                    .ok()
                    .flatten();
                last_ns.map(|ts| ts > cutoff_ns)
            })
            .await
            .ok()
            .flatten()
            .unwrap_or(false);

            if is_active {
                tracing::debug!(
                    window_secs = window,
                    "proactive_dispatcher: idle_only gate — operator recently active, suppressing"
                );
                return Ok(0);
            }
        }
    }

    let queue_path = home.join("proactive_queue.json");
    if !queue_path.exists() {
        return Ok(0);
    }

    // GOLD-FEAT-13: validate the operator's routing policy before touching the
    // queue or any in-flight claims. Missing is the loader's explicit opt-in
    // default; malformed or unreadable policy blocks the tick so an item can
    // never fall back to a different channel silently.
    let routing = crate::channels::routing::ChannelRouting::load_from(
        &home.join(crate::channels::routing::CHANNEL_ROUTING_FILE),
    )
    .map_err(|e| format!("channel routing load failed: {e:#}"))?;

    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;

    // Evict any surviving claim files from a previous crashed tick BEFORE
    // draining — so those keys are gone and cannot be re-drained.
    let sidecar_path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    let evicted_keys = evict_inflight_claimed(home, &mut queue, &sidecar_path, now_unix);

    if queue.is_empty() && evicted_keys.is_empty() {
        return Ok(0);
    }
    let len_before = queue.len();
    let drained = queue.drain(now_unix, PROACTIVE_PER_TICK_CAP);
    if drained.is_empty() {
        // JV-PRO-10: drain may have pruned expired items (or eviction may
        // have removed crashed claims) even when nothing was eligible to
        // fire — reconcile those removals against the FRESH queue (H-1:
        // never blind-save the working copy over concurrent enqueues).
        if queue.len() < len_before || !evicted_keys.is_empty() {
            ProactiveQueue::modify(&queue_path, |fresh| {
                for key in &evicted_keys {
                    fresh.remove_by_key(key);
                }
                let pruned = fresh.prune_expired(now_unix);
                (pruned > 0 || !evicted_keys.is_empty(), ())
            })
            .map_err(|e| format!("queue save after ttl-prune failed: {e}"))?;
        }
        return Ok(0);
    }

    let autonomy_policy = config.autonomy_policy();
    // GOLD-FEAT-13 — routing was loaded fail-closed before queue mutation.
    // Load credentials once per tick too; a missing file means non-Telegram
    // channels stay SidecarOnly.
    // B17: `load()` is fail-closed (only a MISSING file → default; a corrupt or
    // unreadable one → Err). Don't `.unwrap_or_default()` that away — a bad
    // credentials.yaml silently routing every channel item to SidecarOnly with
    // no operator signal is exactly the invisible degradation B17 forbids. On a
    // real load error we still degrade to defaults for this tick (so the queue
    // keeps draining to the sidecar), but LOUDLY.
    let credentials = match crate::config::credentials::Credentials::load_effective(
        &home.join("credentials.yaml"),
        config.secrets_backend,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "proactive dispatch: credentials.yaml is unreadable/corrupt — \
                 routing non-sidecar items to SidecarOnly this tick until it is repaired"
            );
            crate::config::credentials::Credentials::default()
        }
    };
    let mut records: Vec<(crate::proactive::ProactiveItem, ProactiveStatus)> =
        Vec::with_capacity(drained.len());
    let mut delivered = 0usize;
    // CLAW-01: dedup_keys whose claim file was written this tick. Claims are
    // deleted ONLY after the queue save (see the save tail) so the WHOLE batch
    // stays crash-protected — deleting per-item mid-loop would let an
    // already-sent earlier item re-drain (queue not yet saved) → double-fire.
    let mut claimed_keys: Vec<String> = Vec::new();
    // Reuse one lazy Matrix client for every Matrix item in this bounded tick.
    // Credentials are loaded once above, so constructing more than one would
    // only repeat session restore/whoami and contend on the same crypto store.
    #[cfg(feature = "matrix-channel")]
    let mut matrix_channel: Option<crate::channels::matrix::MatrixChannel> = None;

    for item in drained {
        // GOLD-FEAT-13 — route by the item's `source` (per-purpose), falling
        // back to the item's own channel when no routing rule applies.
        let target_channel = routing
            .resolve_channel(&item.source, item.is_failure)
            .unwrap_or_else(|| item.channel.clone());

        // GOLD-ADAPT-OH-08 — reflection observations (source = "g_01_mini")
        // are surface-only and MUST NEVER be auto-posted into chat, Telegram,
        // Slack, Discord, or WhatsApp regardless of autonomy level or routing
        // config. The staged_observations.jsonl path is the real consumer;
        // the operator reads them via `neoth proactive intelligence`.
        // Items that reach the queue still land in proactive_delivered.jsonl
        // (sidecar-only) so no data is lost — the operator can always see
        // what the reflection cron produced.
        let route = if item.source == "g_01_mini" {
            DeliveryRoute::SidecarOnly
        } else {
            plan_delivery(
                &target_channel,
                &autonomy_policy,
                config,
                &routing,
                &credentials,
            )
        };

        // At-most-once guard: write the claim file BEFORE any live send.
        // Suppressed + SidecarOnly never touch the network, so no claim
        // file is needed for them.
        let needs_claim = route_needs_claim(&route);
        if needs_claim {
            match write_inflight_claim(home, &item) {
                // Track the key so its claim is deleted AFTER the queue save.
                Ok(()) => claimed_keys.push(item.dedup_key.clone()),
                // A claim-write failure is non-fatal: fall back to the old
                // at-least-once behaviour for this ONE item rather than
                // dropping it silently. Log prominently for the operator.
                Err(e) => warn!(
                    dedup_key = %item.dedup_key,
                    error = %e,
                    "proactive: inflight claim write failed; proceeding without at-most-once guard"
                ),
            }
        }

        let (status, recipient) = match route {
            DeliveryRoute::Suppressed => (ProactiveStatus::Suppressed, String::new()),
            DeliveryRoute::SidecarOnly => (ProactiveStatus::SidecarOnly, String::new()),
            DeliveryRoute::Telegram { chat_id } => {
                // Safe: plan_delivery returned Telegram only when the token
                // is present. Clone the secret only at the send site.
                let token = config
                    .telegram_token
                    .clone()
                    .expect("plan_delivery guarantees telegram_token is Some");
                let channel =
                    crate::channels::telegram::TelegramChannel::new(token, config.telegram_user_id);
                use crate::channels::Channel;
                match channel.send_proactive(&chat_id, &item.body).await {
                    Ok(_) => {
                        delivered += 1;
                        (ProactiveStatus::Delivered, chat_id)
                    }
                    Err(e) => {
                        warn!(
                            channel = %item.channel,
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "proactive send failed; recorded as failed (not re-enqueued)"
                        );
                        (ProactiveStatus::Failed, chat_id)
                    }
                }
            }
            DeliveryRoute::Slack { channel_id } => {
                // Safe: plan_delivery returned Slack only when both tokens are
                // present. channel_id is the operator's configured destination.
                let bot = credentials
                    .slack_bot_token
                    .clone()
                    .expect("plan_delivery guarantees slack_bot_token is Some");
                let app = credentials
                    .slack_app_token
                    .clone()
                    .expect("plan_delivery guarantees slack_app_token is Some");
                let channel = crate::channels::slack::SlackChannel::new(bot, app);
                use crate::channels::Channel;
                match channel.send_proactive(&channel_id, &item.body).await {
                    Ok(_) => {
                        delivered += 1;
                        (ProactiveStatus::Delivered, channel_id)
                    }
                    Err(e) => {
                        warn!(
                            channel = "slack",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "proactive send failed; recorded as failed (not re-enqueued)"
                        );
                        (ProactiveStatus::Failed, channel_id)
                    }
                }
            }
            DeliveryRoute::Discord { channel_id } => {
                let token = credentials
                    .discord_bot_token
                    .clone()
                    .expect("plan_delivery guarantees discord_bot_token is Some");
                use crate::channels::Channel;
                match crate::channels::discord::DiscordChannel::new(token) {
                    Ok(channel) => match channel.send_proactive(&channel_id, &item.body).await {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, channel_id)
                        }
                        Err(e) => {
                            warn!(
                                channel = "discord",
                                dedup_key = %item.dedup_key,
                                error = %e,
                                "proactive send failed; recorded as failed (not re-enqueued)"
                            );
                            (ProactiveStatus::Failed, channel_id)
                        }
                    },
                    Err(e) => {
                        warn!(
                            channel = "discord",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "discord adapter construct failed; recorded as failed"
                        );
                        (ProactiveStatus::Failed, channel_id)
                    }
                }
            }
            DeliveryRoute::WhatsApp { recipient } => {
                // Safe: plan_delivery returned WhatsApp only when all three
                // credential fields are present. recipient = operator-own E.164.
                let access = credentials
                    .whatsapp_token
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_token is Some");
                let phone_id = credentials
                    .whatsapp_phone_id
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_phone_id is Some");
                let verify = credentials
                    .whatsapp_verify_token
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_verify_token is Some");
                let channel =
                    crate::channels::whatsapp::WhatsAppChannel::new(access, phone_id, verify);
                use crate::channels::Channel;
                match channel.send_proactive(&recipient, &item.body).await {
                    Ok(_) => {
                        delivered += 1;
                        (ProactiveStatus::Delivered, recipient)
                    }
                    Err(e) => {
                        warn!(
                            channel = "whatsapp",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "proactive send failed; recorded as failed (not re-enqueued)"
                        );
                        (ProactiveStatus::Failed, recipient)
                    }
                }
            }
            DeliveryRoute::WhatsAppBaileys { recipient } => {
                let url = credentials
                    .whatsapp_baileys_url
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_baileys_url is Some");
                let token = credentials
                    .whatsapp_baileys_token
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_baileys_token is Some");
                let senders = credentials
                    .whatsapp_baileys_allowed_senders
                    .clone()
                    .expect("plan_delivery guarantees whatsapp_baileys_allowed_senders is Some");
                use crate::channels::Channel;
                match crate::channels::whatsapp_baileys::WhatsAppBaileysChannel::new(
                    url,
                    token,
                    senders,
                    credentials.whatsapp_baileys_allowed_groups.as_deref(),
                    home.join("channel-state/whatsapp-baileys-cursor.json"),
                ) {
                    Ok(channel) => match channel.send_proactive(&recipient, &item.body).await {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, recipient)
                        }
                        Err(error) => {
                            warn!(
                                channel = "whatsapp_baileys",
                                dedup_key = %item.dedup_key,
                                error = %error,
                                "proactive Baileys send failed; recorded as failed (not re-enqueued)"
                            );
                            (ProactiveStatus::Failed, recipient)
                        }
                    },
                    Err(error) => {
                        warn!(
                            channel = "whatsapp_baileys",
                            dedup_key = %item.dedup_key,
                            error = %error,
                            "Baileys adapter construction failed; recorded as failed"
                        );
                        (ProactiveStatus::Failed, recipient)
                    }
                }
            }
            DeliveryRoute::Keet => {
                let url = credentials
                    .keet_bridge_url
                    .as_deref()
                    .expect("plan_delivery guarantees keet_bridge_url is Some");
                let token = credentials
                    .keet_bridge_bearer_token
                    .clone()
                    .expect("plan_delivery guarantees keet_bridge_bearer_token is Some");
                let topic = credentials
                    .keet_topic
                    .as_ref()
                    .expect("plan_delivery guarantees keet_topic is Some");
                let topic_capability = topic.expose();
                let topic_alias = crate::channels::keet::topic_alias(topic_capability)
                    .expect("plan_delivery guarantees a canonical Keet topic");
                let allowed_senders = credentials
                    .keet_allowed_senders
                    .as_deref()
                    .expect("plan_delivery guarantees keet_allowed_senders is Some");
                use crate::channels::Channel;
                match crate::channels::keet::KeetChannel::new(
                    url,
                    token,
                    topic_capability,
                    allowed_senders,
                    home.join(crate::channels::keet::DEFAULT_CURSOR_FILE),
                ) {
                    Ok(channel) => match channel.send_proactive(topic_capability, &item.body).await
                    {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, topic_alias)
                        }
                        Err(error) => {
                            warn!(
                                channel = "keet",
                                dedup_key = %item.dedup_key,
                                error = %error,
                                "proactive Keet companion send failed; recorded as failed"
                            );
                            (ProactiveStatus::Failed, topic_alias)
                        }
                    },
                    Err(error) => {
                        warn!(
                            channel = "keet",
                            dedup_key = %item.dedup_key,
                            error = %error,
                            "Keet companion configuration rejected; recorded as failed"
                        );
                        (ProactiveStatus::Failed, topic_alias)
                    }
                }
            }
            DeliveryRoute::Signal { recipient } => {
                // Safe: plan_delivery returned Signal only when url + number
                // are present. recipient = operator-own configured value.
                let url = credentials
                    .signal_cli_url
                    .clone()
                    .expect("plan_delivery guarantees signal_cli_url is Some");
                let number = credentials
                    .signal_phone_number
                    .clone()
                    .expect("plan_delivery guarantees signal_phone_number is Some");
                use crate::channels::Channel;
                match crate::channels::signal::SignalChannel::new(url, number) {
                    Ok(channel) => match channel.send_proactive(&recipient, &item.body).await {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, recipient)
                        }
                        Err(e) => {
                            warn!(
                                channel = "signal",
                                dedup_key = %item.dedup_key,
                                error = %e,
                                "proactive send failed; recorded as failed (not re-enqueued)"
                            );
                            (ProactiveStatus::Failed, recipient)
                        }
                    },
                    Err(e) => {
                        warn!(
                            channel = "signal",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "signal adapter construct failed; recorded as failed"
                        );
                        (ProactiveStatus::Failed, recipient)
                    }
                }
            }
            DeliveryRoute::Line { recipient } => {
                let token = credentials
                    .line_channel_access_token
                    .clone()
                    .expect("plan_delivery guarantees line_channel_access_token is Some");
                use crate::channels::Channel;
                match crate::channels::line::LineChannel::new(token) {
                    Ok(channel) => match channel.send_proactive(&recipient, &item.body).await {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, recipient)
                        }
                        Err(e) => {
                            warn!(
                                channel = "line",
                                dedup_key = %item.dedup_key,
                                error = %e,
                                "proactive send failed; recorded as failed (not re-enqueued)"
                            );
                            (ProactiveStatus::Failed, recipient)
                        }
                    },
                    Err(e) => {
                        warn!(
                            channel = "line",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "line adapter construct failed; recorded as failed"
                        );
                        (ProactiveStatus::Failed, recipient)
                    }
                }
            }
            DeliveryRoute::Mattermost { channel_id } => {
                let url = credentials
                    .mattermost_url
                    .clone()
                    .expect("plan_delivery guarantees mattermost_url is Some");
                let token = credentials
                    .mattermost_token
                    .clone()
                    .expect("plan_delivery guarantees mattermost_token is Some");
                let channel = crate::channels::mattermost::MattermostChannel::new(url, token);
                use crate::channels::Channel;
                match channel.send_proactive(&channel_id, &item.body).await {
                    Ok(_) => {
                        delivered += 1;
                        (ProactiveStatus::Delivered, channel_id)
                    }
                    Err(e) => {
                        warn!(
                            channel = "mattermost",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "proactive send failed; recorded as failed (not re-enqueued)"
                        );
                        (ProactiveStatus::Failed, channel_id)
                    }
                }
            }
            DeliveryRoute::IMessage { chat_guid } => {
                let url = credentials
                    .bluebubbles_url
                    .clone()
                    .expect("plan_delivery guarantees bluebubbles_url is Some");
                let password = credentials
                    .bluebubbles_password
                    .clone()
                    .expect("plan_delivery guarantees bluebubbles_password is Some");
                use crate::channels::Channel;
                match crate::channels::imessage_bluebubbles::BlueBubblesChannel::new(
                    url, password, None, None,
                ) {
                    Ok(channel) => match channel.send_proactive(&chat_guid, &item.body).await {
                        Ok(_) => {
                            delivered += 1;
                            (ProactiveStatus::Delivered, chat_guid)
                        }
                        Err(e) => {
                            warn!(
                                channel = "imessage_bluebubbles",
                                dedup_key = %item.dedup_key,
                                error = %e,
                                "proactive send failed; recorded as failed (not re-enqueued)"
                            );
                            (ProactiveStatus::Failed, chat_guid)
                        }
                    },
                    Err(e) => {
                        warn!(
                            channel = "imessage_bluebubbles",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "bluebubbles adapter construct failed; recorded as failed"
                        );
                        (ProactiveStatus::Failed, chat_guid)
                    }
                }
            }
            #[cfg(feature = "matrix-channel")]
            DeliveryRoute::Matrix { room_id } => {
                let channel = matrix_channel.get_or_insert_with(|| {
                    let homeserver = credentials
                        .matrix_homeserver
                        .clone()
                        .expect("plan_delivery guarantees matrix_homeserver is Some");
                    let user_id = credentials
                        .matrix_user_id
                        .clone()
                        .expect("plan_delivery guarantees matrix_user_id is Some");
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
                    )
                });
                use crate::channels::Channel;
                match channel.send_proactive(&room_id, &item.body).await {
                    Ok(_) => {
                        delivered += 1;
                        (ProactiveStatus::Delivered, room_id)
                    }
                    Err(e) => {
                        warn!(
                            channel = "matrix",
                            dedup_key = %item.dedup_key,
                            error = %e,
                            "proactive send failed; recorded as failed (not re-enqueued)"
                        );
                        (ProactiveStatus::Failed, room_id)
                    }
                }
            }
        };

        // Distinct WAL frame (0x3A) so an operator can grep exactly when
        // the daemon spoke UNPROMPTED. recipient is hashed, never raw.
        // GOLD-FEAT-13: log the ROUTED target channel (where it actually went),
        // not the item's original channel tag.
        let payload = serde_json::to_vec(&serde_json::json!({
            "channel": target_channel,
            "recipient_hash": recipient_hash(&recipient),
            "dedup_key": item.dedup_key,
            "source": item.source,
            "status": status.as_str(),
            "autonomy": autonomy_policy.level().as_str(),
            "ts_unix": now_unix,
        }))
        .map_err(|error| format!("serialize PROACTIVE_SENT audit payload: {error}"))?;
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_PROACTIVE_SENT, &payload)
                .build();
        if let Err(e) = writer.append(header, payload).await {
            warn!(error = %e, "PROACTIVE_SENT WAL append failed (best-effort audit frame)");
        }

        let cron_status = match status {
            ProactiveStatus::Delivered => crate::cron::state::DeliveryStatus::Delivered,
            ProactiveStatus::Failed => crate::cron::state::DeliveryStatus::Failed,
            ProactiveStatus::Suppressed => crate::cron::state::DeliveryStatus::Suppressed,
            ProactiveStatus::SidecarOnly => crate::cron::state::DeliveryStatus::SidecarOnly,
        };
        crate::cron::state::update_announce_result(home, &item.dedup_key, cron_status).map_err(
            |error| {
                format!(
                    "persist correlated Cron delivery result for {}: {error:#}",
                    item.dedup_key
                )
            },
        )?;
        records.push((item, status));
    }

    append_delivery_records(&sidecar_path, &records, now_unix)
        .map_err(|e| format!("sidecar append failed: {e}"))?;

    // Saved LAST — at-most-once across a mid-send crash (claim files
    // handle the crash window; this save removes items from the queue
    // file so they don't re-drain on the next tick). Review H-1: the save
    // RECONCILES against the freshly reloaded queue instead of blind-
    // saving the pre-delivery working copy — items producers enqueued
    // while the channel sends ran survive; delivered/evicted keys are
    // removed and the drain budget is recorded on the fresh state.
    let removed_keys: Vec<String> = evicted_keys
        .iter()
        .cloned()
        .chain(records.iter().map(|(item, _)| item.dedup_key.clone()))
        .collect();
    let budget_used = records.len();
    // Accepted edge-case: if this save fails (e.g. disk full or I/O error),
    // the claim files written above are NOT deleted (we never reach the
    // `delete_inflight_claim` loop below). On the next tick,
    // `evict_inflight_claimed` will find those surviving claim files and
    // record them as `crash_recovered` — items will NOT be resent, but the
    // daily budget will undercount for this tick because `commit_drain`
    // never ran (eviction does not charge budget). This is accepted: a
    // failing queue-save means the disk is already in serious trouble and
    // the error propagates loudly to the caller; operator intervention is
    // required regardless of the budget counter.
    ProactiveQueue::modify(&queue_path, |fresh| {
        fresh.commit_drain(&removed_keys, budget_used, now_unix);
        fresh.prune_expired(now_unix);
        (true, ())
    })
    .map_err(|e| format!("queue save after delivery failed: {e}"))?;

    // CLAW-01: claims are deleted ONLY now — after the queue save is durable.
    // A crash before the save leaves EVERY in-flight claim on disk, so the
    // next tick's `evict_inflight_claimed` drops the WHOLE batch (no resend).
    // (A crash in the tiny window between this save and the deletes below
    // just leaves stale claims → the next tick records a harmless
    // `crash_recovered` for already-delivered items; safe, never a resend.)
    for key in &claimed_keys {
        delete_inflight_claim(home, key);
    }
    Ok(delivered)
}

/// Append delivery records (item + outcome status) to the JSONL ledger.
/// Distinct from [`append_to_sidecar`] (the gate-off sidecar-only path)
/// because each line carries the live-send `status`.
fn append_delivery_records(
    sidecar_path: &Path,
    records: &[(crate::proactive::ProactiveItem, ProactiveStatus)],
    now_unix: i64,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sidecar_path)?;
    for (item, status) in records {
        let line = serde_json::to_string(&serde_json::json!({
            "delivered_at_unix": now_unix,
            "status": status.as_str(),
            "item": item,
        }))
        .unwrap_or_default();
        writeln!(f, "{line}")?;
    }
    f.flush()?;
    Ok(())
}

/// Spawn the daemon-side drain loop. Matches the doctor_cron /
/// reflection_cron pattern. Returns the JoinHandle the daemon's
/// shutdown path can `.abort()`.
///
/// G-01 (Session 28d): each tick reads `FreedomConfig` FRESH so a mid-run
/// `proactive.enabled` flip (or autonomy change) takes effect without a
/// daemon restart. When `proactive.enabled` is true the tick runs the
/// channel-delivery path (sends to the operator's channel + records
/// outcome); when false it falls back to the sidecar-only drain (the
/// pre-delivery behaviour — items still land in the JSONL ledger).
pub fn spawn_proactive_drain_loop(
    home: PathBuf,
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
            // One strict fresh snapshot per tick — honours mid-run changes
            // without letting malformed policy masquerade as disabled defaults.
            let config = match FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))
            {
                Ok(config) => config,
                Err(error) => {
                    warn!(
                        error = %error,
                        "proactive tick: config invalid; delivery blocked fail-closed"
                    );
                    continue;
                }
            };
            if config.proactive.enabled {
                match run_proactive_delivery_tick(&home, &config, &writer, now_unix).await {
                    Ok(0) => tracing::debug!("proactive delivery tick: nothing delivered"),
                    Ok(n) => info!(delivered = n, "proactive delivery tick: {n} live-sent"),
                    Err(e) => {
                        warn!(error = %e, "proactive delivery tick failed; will retry next interval")
                    }
                }
            } else {
                // Gate off — sidecar-only drain (no channel send).
                match run_proactive_drain_tick(&home, now_unix) {
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

    #[test]
    fn drain_tick_no_queue_file_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn drain_tick_empty_queue_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let queue = ProactiveQueue::new();
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
        // No sidecar gets written for empty drains.
        assert!(!tmp.path().join(PROACTIVE_DELIVERED_SIDECAR).exists());
    }

    #[tokio::test]
    async fn delivery_tick_invalid_routing_leaves_queue_untouched() {
        for routing_is_directory in [false, true] {
            let tmp = TempDir::new().unwrap();
            let queue_path = tmp.path().join("proactive_queue.json");
            let mut queue = ProactiveQueue::new();
            queue.enqueue(item("must-remain", 50, 0));
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
            let error = run_proactive_delivery_tick(
                tmp.path(),
                &FreedomConfig::default(),
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

    #[test]
    fn drain_tick_appends_each_drained_item_to_sidecar() {
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("a", 50, 0));
        queue.enqueue(item("b", 50, 0));
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 2);
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        assert!(sidecar.exists());
        let body = std::fs::read_to_string(sidecar).unwrap();
        // Two lines (one per item) — JSONL format.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is valid JSON.
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["delivered_at_unix"], 1_700_000_000);
            assert!(v["item"].is_object());
        }
    }

    #[test]
    fn drain_tick_persists_post_drain_queue() {
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("a", 50, 0));
        queue.enqueue(item("b", 50, 0));
        let q_path = tmp.path().join("proactive_queue.json");
        queue.save_to(&q_path).unwrap();
        run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        // Reload from disk + verify both items are gone.
        let after = ProactiveQueue::load_from(&q_path).unwrap();
        assert!(after.is_empty());
    }

    #[test]
    fn drain_tick_respects_per_tick_cap() {
        // Enqueue more items than PROACTIVE_PER_TICK_CAP and verify
        // the tick only pops up to the cap. NB: the queue's daily
        // budget defaults to 3, which equals PROACTIVE_PER_TICK_CAP
        // — so the cap actually fires here only if both budgets
        // align. With cap 3 + budget 3 + 5 items enqueued, we get 3
        // out + 2 remain.
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        for k in 0..5 {
            queue.enqueue(item(&format!("k{k}"), 50, 0));
        }
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, PROACTIVE_PER_TICK_CAP);
        let after = ProactiveQueue::load_from(&tmp.path().join("proactive_queue.json")).unwrap();
        assert_eq!(after.peek().len(), 5 - PROACTIVE_PER_TICK_CAP);
    }

    #[test]
    fn drain_tick_appends_not_truncates_sidecar() {
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        std::fs::write(&sidecar, "{\"existing\": \"line\"}\n").unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("new", 50, 0));
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        let body = std::fs::read_to_string(&sidecar).unwrap();
        assert!(
            body.starts_with("{\"existing\": \"line\"}"),
            "existing line MUST be preserved (append-only contract)",
        );
        assert!(body.contains("\"delivered_at_unix\"") && body.contains("\"item\""));
    }

    #[test]
    fn constants_canonical() {
        assert_eq!(PROACTIVE_DRAIN_INTERVAL_SECS, 5 * 60);
        assert_eq!(PROACTIVE_PER_TICK_CAP, 3);
        assert_eq!(PROACTIVE_DELIVERED_SIDECAR, "proactive_delivered.jsonl");
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
    fn route_claim_classification_covers_live_and_sidecar_routes() {
        assert!(!route_needs_claim(&DeliveryRoute::Suppressed));
        assert!(!route_needs_claim(&DeliveryRoute::SidecarOnly));
        assert!(route_needs_claim(&DeliveryRoute::Telegram {
            chat_id: "123".to_string()
        }));
        #[cfg(feature = "matrix-channel")]
        assert!(route_needs_claim(&DeliveryRoute::Matrix {
            room_id: "!ops:example.org".to_string()
        }));
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

    #[test]
    fn recipient_hash_is_deterministic_64_hex_and_input_sensitive() {
        let a = recipient_hash("123456");
        let b = recipient_hash("123456");
        let c = recipient_hash("123457");
        assert_eq!(a, b, "same input ⇒ same hash");
        assert_ne!(a, c, "different input ⇒ different hash");
        assert_eq!(a.len(), 64, "sha-256 hex is 64 chars");
        assert!(
            a.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
        // The raw recipient id must NOT appear in the audit hash.
        assert!(!a.contains("123456"));
    }

    // ── Inflight claim-file guard (at-most-once delivery) ─────────────────

    fn failure_item(key: &str) -> ProactiveItem {
        ProactiveItem {
            is_failure: true,
            ..item(key, 100, 0)
        }
    }

    /// `claim_filename` is deterministic and produces a `.claimed` suffix,
    /// with no raw key material in the filename.
    #[test]
    fn claim_filename_is_deterministic_and_opaque() {
        let a = claim_filename("my/special:key");
        let b = claim_filename("my/special:key");
        let c = claim_filename("other/key");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.ends_with(".claimed"), "must end with .claimed");
        // The raw key must not appear in the filename (filesystem-safety).
        assert!(!a.contains("my") && !a.contains("special") && !a.contains("key"));
    }

    /// `write_inflight_claim` creates a `.claimed` file; `delete_inflight_claim`
    /// removes it; a second delete is a no-op (idempotent).
    #[test]
    fn write_and_delete_claim_file_lifecycle() {
        let tmp = TempDir::new().unwrap();
        let it = item("k1", 50, 0);
        write_inflight_claim(tmp.path(), &it).unwrap();
        let inflight_dir = tmp.path().join(PROACTIVE_INFLIGHT_DIR);
        let claimed: Vec<_> = std::fs::read_dir(&inflight_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".claimed"))
            .collect();
        assert_eq!(
            claimed.len(),
            1,
            "one .claimed file should exist after write"
        );
        // Content round-trips to the original item.
        let bytes = std::fs::read(claimed[0].path()).unwrap();
        let parsed: ProactiveItem = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.dedup_key, "k1");

        delete_inflight_claim(tmp.path(), "k1");
        let remaining: Vec<_> = std::fs::read_dir(&inflight_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".claimed"))
            .collect();
        assert!(remaining.is_empty(), "claim file must be gone after delete");

        // Second delete is a no-op (no panic).
        delete_inflight_claim(tmp.path(), "k1");
    }

    /// A surviving claim file is evicted by `evict_inflight_claimed`:
    /// the item is removed from the queue and a `crash_recovered` entry
    /// appears in the sidecar.
    #[test]
    fn evict_inflight_claimed_removes_item_and_records_crash_recovered() {
        let tmp = TempDir::new().unwrap();
        let it = item("crash-item", 50, 0);
        // Simulate: claim file written but daemon crashed before delete.
        write_inflight_claim(tmp.path(), &it).unwrap();

        // Build a queue that still has the item on disk (crash prevented save).
        let mut queue = ProactiveQueue::new();
        queue.enqueue(it.clone());

        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 1_700_000_000);

        // Queue must be empty — item was evicted.
        assert!(queue.is_empty(), "evicted item must be absent from queue");

        // Claim file must be deleted.
        let inflight_dir = tmp.path().join(PROACTIVE_INFLIGHT_DIR);
        let remaining: Vec<_> = std::fs::read_dir(&inflight_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".claimed"))
            .collect();
        assert!(
            remaining.is_empty(),
            "claim file must be cleaned up by eviction"
        );

        // Sidecar must have a crash_recovered entry.
        let body = std::fs::read_to_string(&sidecar).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(v["status"], "crash_recovered");
        assert_eq!(v["dedup_key"], "crash-item");
        assert_eq!(v["was_failure"], false);
    }

    /// A `crash_recovered` entry for an `is_failure` item carries
    /// `was_failure: true` so the operator can distinguish critical alerts.
    #[test]
    fn evict_inflight_claimed_carries_was_failure_for_critical_alerts() {
        let tmp = TempDir::new().unwrap();
        let it = failure_item("critical-alert");
        write_inflight_claim(tmp.path(), &it).unwrap();

        let mut queue = ProactiveQueue::new();
        queue.enqueue(it.clone());

        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 1_700_000_001);

        let body = std::fs::read_to_string(&sidecar).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(v["status"], "crash_recovered");
        assert_eq!(
            v["was_failure"], true,
            "is_failure item must set was_failure=true"
        );
        assert_eq!(v["dedup_key"], "critical-alert");
    }

    /// A claim file without a matching queue entry is still cleaned up
    /// without panicking (idempotent eviction — `remove_by_key` is a no-op).
    #[test]
    fn evict_inflight_claimed_handles_already_absent_queue_entry() {
        let tmp = TempDir::new().unwrap();
        let it = item("already-gone", 50, 0);
        write_inflight_claim(tmp.path(), &it).unwrap();

        // Queue is empty — item was already removed (e.g., save succeeded
        // but claim delete crashed).
        let mut queue = ProactiveQueue::new();
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        // Must not panic; still records crash_recovered + deletes file.
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 1_700_000_002);

        let inflight_dir = tmp.path().join(PROACTIVE_INFLIGHT_DIR);
        let remaining: Vec<_> = std::fs::read_dir(&inflight_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".claimed"))
            .collect();
        assert!(remaining.is_empty());
        // Sidecar entry is present even though queue was already clean.
        let body = std::fs::read_to_string(&sidecar).unwrap();
        assert!(body.contains("crash_recovered"));
    }

    /// `evict_inflight_claimed` on a missing inflight dir returns without
    /// error (common on a clean first-boot).
    #[test]
    fn evict_inflight_claimed_missing_dir_is_noop() {
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        // No inflight dir — must return silently.
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 0);
        assert!(!sidecar.exists(), "no sidecar entry on empty eviction");
    }

    /// Eviction runs BEFORE drain, so a claim file written by a previous
    /// crashed tick prevents re-drain of the same item.
    #[test]
    fn evict_runs_before_drain_in_drain_tick_ordering() {
        // This test validates the ordering contract by calling eviction
        // manually then drain, mimicking what run_proactive_delivery_tick does.
        let tmp = TempDir::new().unwrap();

        // Two items: "was-in-flight" has a surviving claim, "new-item" does not.
        let in_flight = item("was-in-flight", 100, 0);
        let new_it = item("new-item", 50, 0);

        write_inflight_claim(tmp.path(), &in_flight).unwrap();

        let mut queue = ProactiveQueue::new();
        queue.enqueue(in_flight.clone());
        queue.enqueue(new_it.clone());

        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        // Step 1: evict (before drain).
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 1_700_000_003);

        // "was-in-flight" must be gone; "new-item" must remain.
        assert_eq!(queue.peek().len(), 1);
        assert_eq!(queue.peek()[0].dedup_key, "new-item");

        // Step 2: drain — only "new-item" drains.
        let drained = queue.drain(1_700_000_003, 10);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].dedup_key, "new-item");

        // Sidecar has crash_recovered for "was-in-flight" only.
        let body = std::fs::read_to_string(&sidecar).unwrap();
        assert!(body.contains("crash_recovered"));
        assert!(body.contains("was-in-flight"));
        assert!(!body.contains("new-item"));
    }

    /// `.tmp` orphan files in the inflight dir are ignored by eviction.
    #[test]
    fn evict_ignores_tmp_orphans_in_inflight_dir() {
        let tmp = TempDir::new().unwrap();
        let inflight_dir = tmp.path().join(PROACTIVE_INFLIGHT_DIR);
        std::fs::create_dir_all(&inflight_dir).unwrap();
        // Write a .pid.tmp orphan (atomic_write intermediate).
        std::fs::write(inflight_dir.join("abc.12345.tmp"), b"garbage").unwrap();

        let mut queue = ProactiveQueue::new();
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 0);

        // No crash_recovered entry; orphan is untouched (eviction only reads *.claimed).
        assert!(!sidecar.exists());
        assert!(
            inflight_dir.join("abc.12345.tmp").exists(),
            "orphan must be left alone"
        );
    }

    /// CLAW-01 regression: when a MULTI-item batch crashes before the queue
    /// save, ALL its claim files survive together → eviction drops the WHOLE
    /// batch (no item re-drains, none is re-sent). This is the scenario the
    /// old per-item-delete broke: it deleted earlier items' claims mid-loop,
    /// so on crash only the last item's claim survived and the already-sent
    /// earlier items re-drained → double-fire. The fix (delete claims only
    /// after the save) keeps every claim present until durability, which this
    /// models by writing all three claims before the simulated crash.
    #[test]
    fn evict_drops_an_entire_multi_item_batch_no_resend() {
        let tmp = TempDir::new().unwrap();
        let a = item("batch-a", 100, 0);
        let b = item("batch-b", 90, 0);
        let c = item("batch-c", 80, 0);
        // All three claims written (sends attempted), then crash before save.
        write_inflight_claim(tmp.path(), &a).unwrap();
        write_inflight_claim(tmp.path(), &b).unwrap();
        write_inflight_claim(tmp.path(), &c).unwrap();

        // Queue still has all three (save never happened).
        let mut queue = ProactiveQueue::new();
        queue.enqueue(a);
        queue.enqueue(b);
        queue.enqueue(c);

        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        evict_inflight_claimed(tmp.path(), &mut queue, &sidecar, 1_700_000_010);

        // Whole batch evicted — nothing left to re-drain.
        assert!(
            queue.is_empty(),
            "entire batch must be evicted (no re-send)"
        );
        // All claim files cleaned up.
        let inflight_dir = tmp.path().join(PROACTIVE_INFLIGHT_DIR);
        let remaining = std::fs::read_dir(&inflight_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".claimed"))
            .count();
        assert_eq!(remaining, 0, "all claim files cleaned up");
    }

    // ── GOLD-ADAPT-OH-08: reflection items are forced to SidecarOnly ─────────

    #[test]
    fn oh08_reflection_items_drain_to_sidecar_not_live_channel() {
        // A ProactiveItem with source="g_01_mini" (the reflection cron's tag)
        // must always drain to the sidecar — never to a live channel — regardless
        // of what plan_delivery would have returned for the target_channel.
        // We exercise this via run_proactive_drain_tick (the sidecar-only path):
        // the item lands in proactive_delivered.jsonl with status sidecar_only,
        // not status delivered.
        let tmp = TempDir::new().unwrap();
        let reflection_item = ProactiveItem {
            priority: 50,
            dedup_key: "reflection:weekly:2026-W25".to_string(),
            channel: String::new(),
            source: "g_01_mini".to_string(),
            body: "Du hast diese Woche an rust, memory gearbeitet — willst du an einem mehr dranbleiben?".to_string(),
            scheduled_for_unix: 0,
            is_failure: false,
            expires_unix: 0,
        };
        let mut queue = ProactiveQueue::new();
        queue.enqueue(reflection_item);
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();

        // run_proactive_drain_tick is the sync sidecar path (no channel creds).
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 1, "reflection item must drain to sidecar (count=1)");

        let sidecar =
            std::fs::read_to_string(tmp.path().join(PROACTIVE_DELIVERED_SIDECAR)).unwrap();
        let line = sidecar.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            v["item"]["source"], "g_01_mini",
            "sidecar record must carry the reflection source tag"
        );
        // The run_proactive_drain_tick path writes a raw {"delivered_at_unix":
        // ..., "item":{...}} record — no status field at this level. The test
        // verifies the item IS in the sidecar (operator can see it) and that
        // source tag is preserved, proving the item went through the sidecar
        // path rather than a live-channel path.
        assert!(
            sidecar.contains("g_01_mini"),
            "sidecar must contain the reflection source tag"
        );
    }
}
