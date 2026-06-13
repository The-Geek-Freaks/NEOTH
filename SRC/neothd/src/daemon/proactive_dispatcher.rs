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
//! Keet / Discord) is the L follow-on once each adapter consumes
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

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::FreedomConfig;
use crate::permissions::{Action, AutonomyLevel, evaluate};
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
/// the same file for at-least-once delivery semantics.
pub const PROACTIVE_DELIVERED_SIDECAR: &str = "proactive_delivered.jsonl";

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
    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;
    if queue.is_empty() {
        return Ok(0);
    }
    let drained = queue.drain(now_unix, PROACTIVE_PER_TICK_CAP);
    if drained.is_empty() {
        // Either daily-budget exhausted OR cap=0 OR every item is
        // future-scheduled. Persist nothing + return.
        return Ok(0);
    }

    let sidecar_path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    append_to_sidecar(&sidecar_path, &drained, now_unix)
        .map_err(|e| format!("sidecar append failed: {e}"))?;

    queue
        .save_to(&queue_path)
        .map_err(|e| format!("queue save after drain failed: {e}"))?;
    Ok(drained.len())
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
/// `SidecarOnly` (the operator still sees it in the ledger). Slice 2 wires
/// Telegram/Slack/Discord; WhatsApp/Keet (multi-arg / bridge constructors)
/// land in slice 3 and currently fall to `SidecarOnly`.
pub(crate) fn plan_delivery(
    channel: &str,
    autonomy: AutonomyLevel,
    config: &FreedomConfig,
    routing: &crate::channels::routing::ChannelRouting,
    credentials: &crate::config::credentials::Credentials,
) -> DeliveryRoute {
    let action = Action::ProactiveChannelSend {
        channel: channel.to_string(),
    };
    if !evaluate(&action, autonomy).is_allow() {
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
        _ => DeliveryRoute::SidecarOnly,
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

/// G-01 delivery tick — drains the queue + ACTUALLY SENDS each item to the
/// operator's channel (the slice the consumer-half sidecar left open),
/// then records the outcome. Async because `Channel::send_proactive` is
/// async. Ordering is deliberate for at-least-once delivery: the queue is
/// saved LAST, so a crash mid-send re-drains the item next tick (the
/// `dedup_key` bounds duplicate harm); a duplicate proactive nudge is far
/// less bad than a silently-lost one.
///
/// Returns the number of items LIVE-DELIVERED (status `delivered`).
pub async fn run_proactive_delivery_tick(
    home: &Path,
    config: &FreedomConfig,
    writer: &WalWriterHandle,
    now_unix: i64,
) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    let queue_path = home.join("proactive_queue.json");
    if !queue_path.exists() {
        return Ok(0);
    }
    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;
    if queue.is_empty() {
        return Ok(0);
    }
    let drained = queue.drain(now_unix, PROACTIVE_PER_TICK_CAP);
    if drained.is_empty() {
        return Ok(0);
    }

    let autonomy = config.autonomy;
    // GOLD-FEAT-13 — load the per-purpose routing + credentials ONCE per tick
    // (cheap file reads, mirroring the queue load above). A missing routing
    // file → default (no rules: items keep their own channel / sidecar). A
    // missing credentials file → default (non-Telegram channels → SidecarOnly).
    let routing = crate::channels::routing::ChannelRouting::load_from(
        &home.join(crate::channels::routing::CHANNEL_ROUTING_FILE),
    )
    .unwrap_or_default();
    let credentials = crate::config::credentials::Credentials::load().unwrap_or_default();
    let mut records: Vec<(crate::proactive::ProactiveItem, ProactiveStatus)> =
        Vec::with_capacity(drained.len());
    let mut delivered = 0usize;

    for item in drained {
        // GOLD-FEAT-13 — route by the item's `source` (per-purpose), falling
        // back to the item's own channel when no routing rule applies.
        let target_channel = routing
            .resolve_channel(&item.source, false)
            .unwrap_or_else(|| item.channel.clone());
        let (status, recipient) =
            match plan_delivery(&target_channel, autonomy, config, &routing, &credentials) {
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
            "autonomy": autonomy.as_str(),
            "ts_unix": now_unix,
        }))
        .unwrap_or_default();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_PROACTIVE_SENT, &payload)
                .build();
        if let Err(e) = writer.append(header, payload).await {
            warn!(error = %e, "PROACTIVE_SENT WAL append failed (best-effort audit frame)");
        }

        records.push((item, status));
    }

    let sidecar_path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    append_delivery_records(&sidecar_path, &records, now_unix)
        .map_err(|e| format!("sidecar append failed: {e}"))?;

    // Saved LAST — at-least-once across a mid-send crash.
    queue
        .save_to(&queue_path)
        .map_err(|e| format!("queue save after delivery failed: {e}"))?;
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
            let now_unix = chrono::Utc::now().timestamp();
            // Fresh config read per tick — honours mid-run enable/disable.
            let proactive_enabled = FreedomConfig::load_from_default_path()
                .map(|c| c.proactive.enabled)
                .unwrap_or(false);
            if proactive_enabled {
                let config = match FreedomConfig::load_from_default_path() {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "proactive tick: config reload failed; skipping");
                        continue;
                    }
                };
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

    fn item(key: &str, priority: i32, ts: i64) -> ProactiveItem {
        ProactiveItem {
            priority,
            dedup_key: key.to_string(),
            channel: "cli".to_string(),
            source: "test".to_string(),
            body: format!("test body {key}"),
            scheduled_for_unix: ts,
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
            plan_delivery("telegram", AutonomyLevel::Strict, &cfg, &default_rt(), &default_creds()),
            DeliveryRoute::Suppressed
        );
    }

    #[test]
    fn plan_delivery_standard_suppresses() {
        // Standard ⇒ Confirm ⇒ not Allow ⇒ suppressed (no daemon TTY).
        let cfg = cfg_with_telegram(AutonomyLevel::Standard);
        assert_eq!(
            plan_delivery("telegram", AutonomyLevel::Standard, &cfg, &default_rt(), &default_creds()),
            DeliveryRoute::Suppressed
        );
    }

    #[test]
    fn plan_delivery_elevated_telegram_configured_routes_to_telegram() {
        let cfg = cfg_with_telegram(AutonomyLevel::Elevated);
        assert_eq!(
            plan_delivery("telegram", AutonomyLevel::Elevated, &cfg, &default_rt(), &default_creds()),
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
            plan_delivery("telegram", AutonomyLevel::Elevated, &cfg, &default_rt(), &default_creds()),
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
                plan_delivery(ch, AutonomyLevel::Full, &cfg, &default_rt(), &default_creds()),
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
}
