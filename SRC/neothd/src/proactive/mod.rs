//! G-01a (Session 24) — `ProactiveQueue` shared substrate.
//!
//! A1 + A2 #11 pinned G-01a as the prerequisite for v0.5 PL-03
//! (proactive learning briefings) + OB-03 (Obsidian-as-scratchpad
//! reminders): without a SHARED dedup + rate-limit queue, every
//! proactive producer would create its own notification storm.
//! Operator gets one daily-cap-respecting drainable queue
//! regardless of how many things upstream want to nudge them.
//!
//! ## Item shape
//!
//! `ProactiveItem { priority, dedup_key, channel, source, body,
//! scheduled_for_unix }`. Higher `priority` drains first; ties
//! break on `scheduled_for_unix` (earliest first). The `dedup_key`
//! is the operator-meaningful identity: enqueueing an item whose
//! `dedup_key` matches an already-queued item is a no-op (the
//! prior item wins). Source tag + channel exist so the operator
//! can audit `who-said-what` after the fact via `neoth proactive
//! list --history`.
//!
//! ## Daily cap
//!
//! Default `max_per_day = 3`. `drain(now_unix, cap)` returns up
//! to `cap` items whose `scheduled_for_unix <= now_unix`, in
//! priority-desc order. The queue tracks recent-drain timestamps
//! in a 24h rolling window so a SECOND drain call inside the same
//! window respects the budget left from the first.
//!
//! ## Persistence
//!
//! `save_to(path)` + `load_from(path)` round-trip the queue +
//! drain-history through a JSON file (atomic .tmp + rename). The
//! daemon's bootstrap calls `load_from` to restore queued items
//! across restarts; the drain cron calls `save_to` after every
//! tick so a crash mid-tick doesn't lose state.
//!
//! ## Scope of this commit (G-01a)
//!
//! - In-memory queue + dedup + priority + daily-cap drain.
//! - Persistence helpers (save / load).
//! - Tests covering every behaviour.
//!
//! Producer-side wiring (G-01-mini reflection cron, PL-03, OB-03,
//! Self-correction loop) is the next commit set — those callers
//! consume `ProactiveQueue::enqueue`. The shared substrate
//! unblocks them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod action_staging;

/// One queued proactive notification. Fields are operator-facing —
/// the CLI's `neoth proactive list` renders each verbatim, and the
/// audit trail records the full struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProactiveItem {
    /// Higher fires first. Operator-defined; rough convention:
    ///   - 100 = "urgent — operator asked for it"
    ///   - 50  = "useful unprompted nudge"
    ///   - 10  = "background telemetry observation"
    pub priority: i32,
    /// Operator-meaningful identity. Duplicate enqueues are no-ops.
    /// Convention: `"<producer>:<topic>:<window>"` so a daily-briefing
    /// dedup key `"reflection:morning-news:2026-05-25"` won't enqueue
    /// twice within the same day even if the cron fires multiple times.
    pub dedup_key: String,
    /// Channel target by name as recognised by `channels::Channel::name`
    /// (`telegram` / `slack` / `cli`). Empty falls back to
    /// the operator's default channel.
    pub channel: String,
    /// Producer tag for audit. e.g. `"g_01_mini"` / `"pl_03"` /
    /// `"ob_03"` / `"self_correction"`.
    pub source: String,
    /// The notification body the operator sees. Pre-rendered;
    /// channel adapters apply their own formatting on top.
    pub body: String,
    /// Earliest unix-seconds time this item may drain. `drain` skips
    /// items whose `scheduled_for_unix > now_unix`. Default 0 =
    /// drain immediately.
    pub scheduled_for_unix: i64,
    /// GOLD-FEAT-13 — when `true`, channel routing prefers the operator's
    /// configured `failure_channel` (e.g. a coding session that ended with
    /// blocked tasks). `#[serde(default)]` so queue files written before this
    /// field deserialise as non-failure.
    #[serde(default)]
    pub is_failure: bool,
    /// JV-PRO-10 — TTL. Unix-seconds after which a still-queued item is
    /// DROPPED on the next `drain` without ever firing (a stale nudge —
    /// e.g. yesterday's news held back by the daily cap — is worse than no
    /// nudge). `0` = never expires. `#[serde(default)]` so queue files
    /// written before this field load as evergreen. Producers of
    /// time-sensitive items set it; evergreen items leave it `0`.
    #[serde(default)]
    pub expires_unix: i64,
}

/// JV-PRO-10 — items at/above this priority "early-surface": they bypass
/// `scheduled_for_unix` (drain before their scheduled time). NOTE (D53): this
/// bypasses only the SCHEDULE, not the daily cap — `take_n = cap.min(budget_left)`
/// still applies, so once the per-day budget is exhausted even an urgent item
/// drains nothing until the next day. This is the operator-urgent / signal path
/// (the upstream "DSPM signal" → surface now), matching the priority-100
/// "urgent — operator asked for it" convention above.
pub const URGENT_PRIORITY: i32 = 100;

/// Keep disk input compatible with the egress claim bound. Invalid queue
/// entries are rejected before selection so malformed JSON can never reach the
/// generation lookup as a production panic.
pub(crate) const MAX_PROACTIVE_DEDUP_KEY_BYTES: usize = 4_096;
pub(crate) const MAX_PROACTIVE_CHANNEL_BYTES: usize = 64;
pub(crate) const MAX_PROACTIVE_SOURCE_BYTES: usize = 4_096;
pub(crate) const MAX_PROACTIVE_BODY_BYTES: usize = 1024 * 1024;
/// Leaves at least 128 KiB for the smallest downstream history-record envelope
/// while still allowing an exact 1 MiB ordinary-text body. This extra encoded
/// bound is required because JSON control-character escaping can expand a byte
/// sixfold.
pub(crate) const MAX_PROACTIVE_ITEM_ENCODED_BYTES: usize = 1152 * 1024;
const MAX_QUEUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_QUEUE_ITEMS: usize = 10_000;
const MAX_DRAIN_HISTORY: usize = 100_000;
const MAX_SETTLED_EGRESS_INTENTS: usize = 4_096;
const MAX_QUARANTINED_ITEMS: usize = MAX_QUEUE_ITEMS;
const QUARANTINED_ITEM_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProactiveItemInvalidity {
    EmptyDedupKey,
    DedupKeyTooLarge,
    ChannelTooLarge,
    SourceTooLarge,
    BodyTooLarge,
    EncodedItemTooLarge,
    ItemEncodingFailed,
    DuplicateDedupKey,
}

impl std::fmt::Display for ProactiveItemInvalidity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyDedupKey => "proactive dedup key is empty",
            Self::DedupKeyTooLarge => "proactive dedup key exceeds 4096 bytes",
            Self::ChannelTooLarge => "proactive channel exceeds 64 bytes",
            Self::SourceTooLarge => "proactive source exceeds 4096 bytes",
            Self::BodyTooLarge => "proactive body exceeds 1048576 bytes",
            Self::EncodedItemTooLarge => "serialized proactive item exceeds 1179648 bytes",
            Self::ItemEncodingFailed => "proactive item could not be serialized",
            Self::DuplicateDedupKey => "proactive dedup key duplicates an earlier queue item",
        })
    }
}

impl std::error::Error for ProactiveItemInvalidity {}

impl ProactiveItem {
    /// The single item-shape authority shared by producer admission, persisted
    /// queue migration and durable egress. Limits are byte limits because the
    /// serialized/channel payload is byte-addressed, not Unicode-scalar based.
    pub(crate) fn validate(&self) -> std::result::Result<(), ProactiveItemInvalidity> {
        if self.dedup_key.is_empty() {
            return Err(ProactiveItemInvalidity::EmptyDedupKey);
        }
        if self.dedup_key.len() > MAX_PROACTIVE_DEDUP_KEY_BYTES {
            return Err(ProactiveItemInvalidity::DedupKeyTooLarge);
        }
        if self.channel.len() > MAX_PROACTIVE_CHANNEL_BYTES {
            return Err(ProactiveItemInvalidity::ChannelTooLarge);
        }
        if self.source.len() > MAX_PROACTIVE_SOURCE_BYTES {
            return Err(ProactiveItemInvalidity::SourceTooLarge);
        }
        if self.body.len() > MAX_PROACTIVE_BODY_BYTES {
            return Err(ProactiveItemInvalidity::BodyTooLarge);
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| ProactiveItemInvalidity::ItemEncodingFailed)?;
        if encoded.len() > MAX_PROACTIVE_ITEM_ENCODED_BYTES {
            return Err(ProactiveItemInvalidity::EncodedItemTooLarge);
        }
        Ok(())
    }
}

/// Secret-safe evidence for one item removed during persisted-queue
/// normalization. No operator content, channel, source or dedup key is copied
/// into this record; the domain-separated digest binds the exact discarded
/// item for forensic correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantinedProactiveItem {
    version: u8,
    reason: ProactiveItemInvalidity,
    item_sha256: String,
    dedup_key_bytes: usize,
    channel_bytes: usize,
    #[serde(default)]
    source_bytes: usize,
    body_bytes: usize,
    #[serde(default)]
    encoded_bytes: usize,
}

impl QuarantinedProactiveItem {
    fn from_item(item: &ProactiveItem, reason: ProactiveItemInvalidity) -> Result<Self> {
        let item_bytes =
            serde_json::to_vec(item).context("encode quarantined proactive item digest")?;
        Ok(Self {
            version: QUARANTINED_ITEM_VERSION,
            reason,
            item_sha256: crate::wal::events::effect_digest(
                b"proactive-queue-quarantined-item-v1",
                &item_bytes,
            ),
            dedup_key_bytes: item.dedup_key.len(),
            channel_bytes: item.channel.len(),
            source_bytes: item.source.len(),
            body_bytes: item.body.len(),
            encoded_bytes: item_bytes.len(),
        })
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == QUARANTINED_ITEM_VERSION,
            "unsupported proactive quarantine evidence version"
        );
        anyhow::ensure!(
            self.item_sha256.len() == 64
                && self
                    .item_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "proactive quarantine evidence has an invalid item digest"
        );
        Ok(())
    }
}

/// Daily-cap configuration. `max_per_day = 3` is the AGENTER hard-
/// rule default for proactive messages (operator opt-in beyond
/// that via `neoth proactive config --max-per-day N`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProactiveConfig {
    pub max_per_day: usize,
}

impl Default for ProactiveConfig {
    fn default() -> Self {
        Self { max_per_day: 3 }
    }
}

/// The in-memory proactive queue. Cheaply clonable via `Arc<Mutex<_>>`
/// at the wrapper layer when shared across producers — this struct
/// itself owns its state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProactiveQueue {
    items: Vec<ProactiveItem>,
    /// Recent drain timestamps (unix-seconds). The daily-cap check
    /// counts entries within `now - 86_400 < ts <= now`. Pruned
    /// inside `drain` to keep the vector bounded.
    drained_at: Vec<i64>,
    #[serde(default)]
    pub config: ProactiveConfig,
    /// Durable idempotency tombstones for terminal proactive egress intents.
    /// A result projection records its UUIDv7 here in the same atomic queue
    /// transaction that removes the item and charges the daily budget.  A
    /// crash after that commit but before claim deletion therefore cannot
    /// remove or charge a producer's later re-enqueue of the same dedup key.
    #[serde(default)]
    settled_egress_intents: BTreeSet<String>,
    /// Immutable generation for each queued dedup key. Settlement removes only
    /// the generation that was admitted before transport; a producer may drop
    /// and re-enqueue the same key during network I/O without losing the new
    /// item.
    #[serde(default)]
    item_generations: BTreeMap<String, String>,
    /// Bounded forensic ring for parseable-but-invalid persisted items. This
    /// lets one malformed item be removed durably without discarding or
    /// starving the valid remainder of the queue.
    #[serde(default)]
    quarantined_items: Vec<QuarantinedProactiveItem>,
    /// In-memory migration marker. `modify` persists normalization even when
    /// its caller performs no mutation, so a poisoned front item cannot return
    /// on every tick. Never serialized.
    #[serde(skip)]
    normalization_dirty: bool,
}

/// Review H-1 (2026-07-03) — process-global lock serialising every
/// load→mutate→save cycle on `proactive_queue.json`. Producers (cluster
/// accept notices, crons) and the drain loop all run in the daemon
/// process; without it two overlapping cycles silently lose the slower
/// writer's update (atomic rename prevents torn FILES, not lost updates).
/// Callers use [`ProactiveQueue::modify`]; bare `load_from`/`save_to`
/// stays for single-writer contexts (tests, one-shot CLI).
static QUEUE_FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Cross-process sibling lock shared by daemon producers, one-shot CLIs and
/// the proactive delivery/recovery path.
pub const PROACTIVE_QUEUE_LOCK_FILE: &str = "proactive_queue.lock";

impl ProactiveQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Locked load→mutate→save cycle. `f` returns `(persist, out)` —
    /// `persist=false` skips the write for no-op mutations. A missing
    /// file loads as the empty queue (same contract as `load_from`).
    pub fn modify<T>(path: &Path, f: impl FnOnce(&mut Self) -> (bool, T)) -> Result<T> {
        let _guard = QUEUE_FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let lock_path = if path
            .file_name()
            .is_some_and(|name| name == "proactive_queue.json")
        {
            path.with_file_name(PROACTIVE_QUEUE_LOCK_FILE)
        } else {
            path.with_extension("lock")
        };
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &lock_path,
            "proactive queue transaction",
        )?;
        let mut queue = Self::load_from(path)?;
        let normalization_dirty = std::mem::take(&mut queue.normalization_dirty);
        let (persist, out) = f(&mut queue);
        if persist || normalization_dirty {
            queue.save_to(path)?;
        }
        Ok(out)
    }

    pub fn with_config(config: ProactiveConfig) -> Self {
        Self {
            items: Vec::new(),
            drained_at: Vec::new(),
            config,
            settled_egress_intents: BTreeSet::new(),
            item_generations: BTreeMap::new(),
            quarantined_items: Vec::new(),
            normalization_dirty: false,
        }
    }

    fn validate_non_item_state(&self) -> Result<()> {
        anyhow::ensure!(
            self.items.len() <= MAX_QUEUE_ITEMS,
            "proactive queue item count exceeds limit"
        );
        anyhow::ensure!(
            self.drained_at.len() <= MAX_DRAIN_HISTORY,
            "proactive queue drain history exceeds limit"
        );
        anyhow::ensure!(
            self.settled_egress_intents.len() <= MAX_SETTLED_EGRESS_INTENTS,
            "proactive queue settlement count exceeds limit"
        );
        anyhow::ensure!(
            self.quarantined_items.len() <= MAX_QUARANTINED_ITEMS,
            "proactive queue quarantine evidence count exceeds limit"
        );
        for intent_id in &self.settled_egress_intents {
            let parsed = uuid::Uuid::parse_str(intent_id)
                .context("parse proactive queue settlement intent id")?;
            anyhow::ensure!(
                parsed.get_version_num() == 7 && parsed.hyphenated().to_string() == *intent_id,
                "proactive queue contains a non-canonical settlement intent id"
            );
        }
        for record in &self.quarantined_items {
            record.validate()?;
        }
        Ok(())
    }

    fn quarantine_item(
        &mut self,
        item: &ProactiveItem,
        reason: ProactiveItemInvalidity,
    ) -> Result<()> {
        self.quarantined_items
            .push(QuarantinedProactiveItem::from_item(item, reason)?);
        if self.quarantined_items.len() > MAX_QUARANTINED_ITEMS {
            let excess = self.quarantined_items.len() - MAX_QUARANTINED_ITEMS;
            self.quarantined_items.drain(..excess);
        }
        Ok(())
    }

    fn normalize_item_generations(&mut self) -> Result<()> {
        self.validate_non_item_state()?;
        let original_items = std::mem::take(&mut self.items);
        let original_generations = self.item_generations.clone();
        let mut active = BTreeSet::new();
        let mut quarantined_generation_keys = BTreeSet::new();
        let mut retained = Vec::with_capacity(original_items.len());
        let mut normalized = false;
        for item in original_items {
            let invalidity = item.validate().err().or_else(|| {
                if active.contains(item.dedup_key.as_str()) {
                    Some(ProactiveItemInvalidity::DuplicateDedupKey)
                } else {
                    None
                }
            });
            if let Some(reason) = invalidity {
                quarantined_generation_keys.insert(item.dedup_key.clone());
                self.quarantine_item(&item, reason)?;
                normalized = true;
                continue;
            }
            active.insert(item.dedup_key.clone());
            retained.push(item);
        }
        self.items = retained;
        self.item_generations
            .retain(|dedup_key, _| active.contains(dedup_key.as_str()));
        for dedup_key in quarantined_generation_keys {
            self.item_generations.remove(&dedup_key);
        }
        for item in &self.items {
            if self.item_generations.contains_key(&item.dedup_key) {
                continue;
            }
            let bytes =
                serde_json::to_vec(item).context("serialise legacy proactive item generation")?;
            self.item_generations.insert(
                item.dedup_key.clone(),
                crate::wal::events::effect_digest(b"proactive-queue-legacy-entry-v1", &bytes),
            );
        }
        anyhow::ensure!(
            self.item_generations.len() == self.items.len()
                && self.item_generations.iter().all(|(dedup_key, generation)| {
                    active.contains(dedup_key.as_str())
                        && !generation.is_empty()
                        && generation.len() <= 64
                }),
            "proactive queue generation map violates its exact item invariant"
        );
        normalized |= self.item_generations != original_generations;
        self.normalization_dirty |= normalized;
        Ok(())
    }

    fn validate_invariants(&self) -> Result<()> {
        self.validate_non_item_state()?;
        let mut active = BTreeSet::new();
        for item in &self.items {
            item.validate().map_err(anyhow::Error::new)?;
            anyhow::ensure!(
                active.insert(item.dedup_key.as_str()),
                "proactive queue contains duplicate dedup keys"
            );
        }
        anyhow::ensure!(
            self.item_generations.len() == self.items.len()
                && self.item_generations.iter().all(|(dedup_key, generation)| {
                    active.contains(dedup_key.as_str())
                        && !generation.is_empty()
                        && generation.len() <= 64
                }),
            "proactive queue generation map violates its exact item invariant"
        );
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Enqueue `item`. Returns `true` on insert, `false` when the
    /// `dedup_key` already exists in the queue (prior item wins,
    /// matches the spec).
    pub fn enqueue(&mut self, item: ProactiveItem) -> Result<bool> {
        item.validate()
            .map_err(anyhow::Error::new)
            .context("validate proactive item before enqueue")?;
        if self.items.iter().any(|i| i.dedup_key == item.dedup_key) {
            return Ok(false);
        }
        self.item_generations
            .insert(item.dedup_key.clone(), uuid::Uuid::now_v7().to_string());
        self.items.push(item);
        Ok(true)
    }

    /// Cross-process-safe enqueue for the common one-item producer path.
    /// Validation failures are returned to the producer and never turn into a
    /// claimed successful/no-op enqueue.
    pub fn enqueue_at(path: &Path, item: ProactiveItem) -> Result<bool> {
        Self::modify(path, |queue| match queue.enqueue(item) {
            Ok(inserted) => (inserted, Ok(inserted)),
            Err(error) => (false, Err(error)),
        })?
    }

    /// Immutable generation of the currently queued item for `dedup_key`.
    pub fn entry_generation(&self, dedup_key: &str) -> Option<&str> {
        self.item_generations.get(dedup_key).map(String::as_str)
    }

    /// Pop up to `cap` items in priority-desc order, capped by both
    /// `cap` and the remaining daily-budget (per `config.max_per_day`).
    /// Records the wall-clock of each drained item so subsequent
    /// drains within the same 24h window respect the budget.
    ///
    /// `now_unix` is injected so tests can simulate arbitrary clock
    /// positions without sleeping; production callers pass the real
    /// wall clock.
    pub fn drain(&mut self, now_unix: i64, cap: usize) -> Vec<ProactiveItem> {
        self.drain_with_generations(now_unix, cap)
            .into_iter()
            .map(|(item, _)| item)
            .collect()
    }

    /// Drain with the immutable queue generation needed by durable egress.
    pub fn drain_with_generations(
        &mut self,
        now_unix: i64,
        cap: usize,
    ) -> Vec<(ProactiveItem, String)> {
        // JV-PRO-10 — drop expired items BEFORE anything else (even before
        // the budget check), so a stale nudge never fires and an exhausted
        // daily budget can't keep dead items alive on disk.
        self.prune_expired(now_unix);
        let cutoff = now_unix.saturating_sub(86_400);
        self.drained_at.retain(|t| *t > cutoff);
        let used_today = self.drained_at.len();
        let budget_left = self.config.max_per_day.saturating_sub(used_today);
        let take_n = cap.min(budget_left);
        if take_n == 0 {
            return Vec::new();
        }

        // Index-based selection so we can pull from the middle of
        // the vec without an O(n log n) sort allocation per drain.
        let mut eligible: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            // JV-PRO-10 — an item drains once its schedule arrives, OR
            // immediately if it is operator-urgent (early-surface bypass).
            .filter(|(_, i)| i.scheduled_for_unix <= now_unix || i.priority >= URGENT_PRIORITY)
            .map(|(idx, _)| idx)
            .collect();
        eligible.sort_by(|a, b| {
            self.items[*b]
                .priority
                .cmp(&self.items[*a].priority)
                .then_with(|| {
                    self.items[*a]
                        .scheduled_for_unix
                        .cmp(&self.items[*b].scheduled_for_unix)
                })
        });
        eligible.truncate(take_n);

        // Remove from highest index downward so prior indices stay valid.
        eligible.sort_unstable_by(|a, b| b.cmp(a));
        let mut out: Vec<(ProactiveItem, String)> = eligible
            .into_iter()
            .map(|idx| {
                let item = self.items.remove(idx);
                let generation = self
                    .item_generations
                    .remove(&item.dedup_key)
                    .unwrap_or_else(|| {
                        // `ProactiveQueue` is publicly deserializable for API
                        // compatibility, so callers can bypass `load_from`.
                        // Repair that legacy/malformed in-memory case without a
                        // production panic; persisted queues still fail closed
                        // through `validate_invariants`.
                        let bytes = serde_json::to_vec(&item)
                            .unwrap_or_else(|_| item.dedup_key.as_bytes().to_vec());
                        crate::wal::events::effect_digest(
                            b"proactive-queue-legacy-entry-v1",
                            &bytes,
                        )
                    });
                (item, generation)
            })
            .collect();
        // Restore priority-desc order for the caller (the index
        // removal above pulled them in descending-index, which is
        // unrelated to priority).
        out.sort_by_key(|(item, _)| std::cmp::Reverse(item.priority));
        for _ in &out {
            self.drained_at.push(now_unix);
        }
        out
    }

    /// Review H-1 — reconcile a completed drain against the FRESH on-disk
    /// queue: remove every delivered/evicted key and record `budget_used`
    /// drain timestamps. Used inside [`Self::modify`] at the delivery
    /// tick's save point so items producers enqueued WHILE sends ran are
    /// never lost to a blind save of the pre-delivery working copy.
    pub fn commit_drain(&mut self, removed_keys: &[String], budget_used: usize, now_unix: i64) {
        for key in removed_keys {
            self.remove_by_key(key);
        }
        for _ in 0..budget_used {
            self.drained_at.push(now_unix);
        }
    }

    /// Atomically project one terminal proactive egress result into the queue.
    /// Returns `true` only for the first settlement of `intent_id`.
    ///
    /// The tombstone check happens before touching `dedup_key`. This ordering
    /// is load-bearing: after a crash between queue commit and claim removal,
    /// recovery sees the old result again but must preserve a newly enqueued
    /// item that happens to reuse the same producer dedup key.
    pub fn settle_egress_once(
        &mut self,
        intent_id: &str,
        dedup_key: &str,
        entry_generation: &str,
        now_unix: i64,
    ) -> bool {
        if self.egress_intent_is_settled(intent_id) {
            return false;
        }
        self.settled_egress_intents.insert(intent_id.to_string());
        if self.entry_generation(dedup_key) == Some(entry_generation) {
            self.remove_by_key(dedup_key);
        }
        let cutoff = now_unix.saturating_sub(86_400);
        self.drained_at.retain(|timestamp| *timestamp > cutoff);
        self.drained_at.push(now_unix);
        true
    }

    /// Whether an egress result is already projected while its durable claim
    /// remains recoverable.
    pub fn egress_intent_is_settled(&self, intent_id: &str) -> bool {
        self.settled_egress_intents.contains(intent_id)
    }

    /// Forget one exact tombstone only after its claim deletion is durably
    /// committed. Other active claims remain protected during batch recovery.
    pub fn forget_settled_egress_intent(&mut self, intent_id: &str) -> bool {
        self.settled_egress_intents.remove(intent_id)
    }

    /// Garbage-collect settlement tombstones once the durable claim directory
    /// proves there are no in-flight egress transactions left to replay.
    pub(crate) fn clear_settled_egress_intents(&mut self) -> bool {
        let changed = !self.settled_egress_intents.is_empty();
        self.settled_egress_intents.clear();
        changed
    }

    /// JV-PRO-10 expiry prune, callable outside `drain` (the reconcile
    /// path re-prunes the fresh queue). Returns the number dropped.
    pub fn prune_expired(&mut self, now_unix: i64) -> usize {
        let before = self.items.len();
        self.items
            .retain(|i| i.expires_unix == 0 || i.expires_unix > now_unix);
        let active = self
            .items
            .iter()
            .map(|item| item.dedup_key.as_str())
            .collect::<BTreeSet<_>>();
        self.item_generations
            .retain(|dedup_key, _| active.contains(dedup_key.as_str()));
        before - self.items.len()
    }

    /// Peek at items currently in the queue (immutable view). Useful
    /// for `neoth proactive list` without consuming the queue.
    pub fn peek(&self) -> &[ProactiveItem] {
        &self.items
    }

    /// Remaining daily budget. Returns `config.max_per_day` minus
    /// the count of drains within the last 24h. Pure read; doesn't
    /// mutate the rolling window.
    pub fn budget_left(&self, now_unix: i64) -> usize {
        let cutoff = now_unix.saturating_sub(86_400);
        let used = self.drained_at.iter().filter(|t| **t > cutoff).count();
        self.config.max_per_day.saturating_sub(used)
    }

    /// Drop every item whose `dedup_key` matches `key`. Returns the
    /// number removed. Used by `neoth proactive drop <key>` for an
    /// operator who decided a queued nudge isn't relevant anymore.
    pub fn remove_by_key(&mut self, key: &str) -> usize {
        let before = self.items.len();
        self.items.retain(|i| i.dedup_key != key);
        self.item_generations.remove(key);
        before - self.items.len()
    }

    /// Atomic save via `.tmp` + rename. Mode 0600 on unix; restricted
    /// DACL on Windows via the credentials helper. Mirrors the
    /// pattern used by `wizard_checkpoint::save_checkpoint`.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        self.validate_invariants()
            .context("validate proactive queue before save")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {}", path.display()))?;
        }
        let bytes = serde_json::to_vec(self).context("serialise proactive queue")?;
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_QUEUE_BYTES,
            "proactive queue exceeds serialized byte limit"
        );
        crate::util::atomic_write::atomic_write_private(path, &bytes)
            .with_context(|| format!("atomically write private queue {}", path.display()))?;
        crate::util::atomic_write::sync_parent_directory_required(path)
            .with_context(|| format!("durably commit private queue {}", path.display()))?;
        Ok(())
    }

    /// Read the queue from disk. Returns `Ok(Self::default())` when
    /// the file is missing so a fresh-install daemon can call this
    /// unconditionally. A published zero-length file is corruption: atomic
    /// writers never expose one and silently treating it as empty could erase
    /// delivery authority.
    pub fn load_from(path: &Path) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "proactive queue is not a regular file"
        );
        anyhow::ensure!(
            metadata.len() > 0 && metadata.len() <= MAX_QUEUE_BYTES,
            "proactive queue byte length is invalid"
        );
        #[cfg(unix)]
        let metadata = {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .context("make legacy proactive queue private")?;
                file.sync_all()
                    .context("durably persist legacy proactive queue mode")?;
                let migrated = file
                    .metadata()
                    .context("reinspect migrated proactive queue mode")?;
                anyhow::ensure!(
                    migrated.permissions().mode() & 0o077 == 0,
                    "proactive queue permission migration did not stick"
                );
                migrated
            } else {
                metadata
            }
        };
        #[cfg(windows)]
        if crate::wal::win_native::verify_private_file_handle(&file).is_err() {
            crate::wal::win_native::set_private_current_user_file_dacl_bound(path, &file)
                .context("make bound legacy proactive queue DACL private and durable")?;
            crate::wal::win_native::verify_private_file_handle(&file)
                .context("verify migrated proactive queue private DACL")?;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_QUEUE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= MAX_QUEUE_BYTES,
            "proactive queue changed during bounded read"
        );
        let mut queue: Self =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        queue.normalize_item_generations()?;
        Ok(queue)
    }

    /// Stats snapshot for the operator-facing `neoth proactive
    /// status` line. Pure-read.
    pub fn stats(&self, now_unix: i64) -> QueueStats {
        let cutoff = now_unix.saturating_sub(86_400);
        let drained_24h = self.drained_at.iter().filter(|t| **t > cutoff).count();
        let by_source: HashMap<String, usize> =
            self.items.iter().fold(HashMap::new(), |mut acc, i| {
                *acc.entry(i.source.clone()).or_insert(0) += 1;
                acc
            });
        QueueStats {
            queued: self.items.len(),
            drained_last_24h: drained_24h,
            budget_left: self.budget_left(now_unix),
            by_source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueStats {
    pub queued: usize,
    pub drained_last_24h: usize,
    pub budget_left: usize,
    pub by_source: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn item(priority: i32, key: &str, source: &str) -> ProactiveItem {
        ProactiveItem {
            priority,
            dedup_key: key.into(),
            channel: "telegram".into(),
            source: source.into(),
            body: format!("body of {key}"),
            scheduled_for_unix: 0,
            is_failure: false,
            expires_unix: 0,
        }
    }

    #[test]
    fn expired_item_is_dropped_without_firing() {
        let mut q = ProactiveQueue::new();
        // expires at t=100; draining at t=200 must drop it, not fire it.
        q.enqueue(ProactiveItem {
            expires_unix: 100,
            ..item(50, "stale-news", "hn_tech_currency")
        })
        .unwrap();
        q.enqueue(item(50, "evergreen", "x")).unwrap(); // expires_unix 0 = never
        let drained = q.drain(200, 10);
        assert_eq!(drained.len(), 1, "only the evergreen item should fire");
        assert_eq!(drained[0].dedup_key, "evergreen");
        assert_eq!(q.len(), 0, "expired item must be pruned from the queue too");
    }

    #[test]
    fn not_yet_expired_item_still_fires() {
        let mut q = ProactiveQueue::new();
        q.enqueue(ProactiveItem {
            expires_unix: 1000,
            ..item(50, "fresh", "x")
        })
        .unwrap();
        let drained = q.drain(500, 10);
        assert_eq!(drained.len(), 1, "item expiring later must still fire now");
    }

    #[test]
    fn urgent_item_early_surfaces_past_its_schedule() {
        let mut q = ProactiveQueue::new();
        // Scheduled far in the future, but URGENT_PRIORITY → drains now.
        q.enqueue(ProactiveItem {
            priority: URGENT_PRIORITY,
            scheduled_for_unix: 9_999,
            ..item(URGENT_PRIORITY, "urgent-signal", "x")
        })
        .unwrap();
        // A non-urgent future item must NOT early-surface.
        q.enqueue(ProactiveItem {
            scheduled_for_unix: 9_999,
            ..item(50, "later", "x")
        })
        .unwrap();
        let drained = q.drain(0, 10);
        assert_eq!(
            drained.len(),
            1,
            "only the urgent item bypasses its schedule"
        );
        assert_eq!(drained[0].dedup_key, "urgent-signal");
    }

    #[test]
    fn new_queue_is_empty_with_default_budget() {
        let q = ProactiveQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.budget_left(0), 3, "default max_per_day = 3");
    }

    #[test]
    fn enqueue_dedups_on_key() {
        let mut q = ProactiveQueue::new();
        assert!(q.enqueue(item(50, "k1", "a")).unwrap());
        assert!(
            !q.enqueue(item(99, "k1", "b")).unwrap(),
            "duplicate key must reject"
        );
        assert_eq!(q.len(), 1);
        // The PRIOR item wins per spec — body still reflects "a".
        assert_eq!(q.peek()[0].source, "a");
    }

    #[test]
    fn drain_pops_in_priority_desc_order_and_breaks_ties_by_schedule() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "low", "x")).unwrap();
        q.enqueue(item(50, "mid1", "x")).unwrap();
        // Same priority as mid1 but scheduled earlier — wins the tie.
        q.enqueue(ProactiveItem {
            scheduled_for_unix: -1,
            ..item(50, "mid2-earlier", "x")
        })
        .unwrap();
        q.enqueue(item(100, "urgent", "x")).unwrap();

        let drained = q.drain(0, 10);
        assert_eq!(drained.len(), 3, "default max_per_day = 3");
        // Priority-desc.
        assert_eq!(drained[0].dedup_key, "urgent");
        // Tie at 50 — earlier-scheduled one wins.
        assert_eq!(drained[1].dedup_key, "mid2-earlier");
        assert_eq!(drained[2].dedup_key, "mid1");
        // `low` stays queued because the daily cap was hit.
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek()[0].dedup_key, "low");
    }

    #[test]
    fn drain_respects_daily_cap_across_multiple_calls_in_same_window() {
        let mut q = ProactiveQueue::new();
        for i in 0..10 {
            q.enqueue(item(10, &format!("k{i}"), "x")).unwrap();
        }
        // First drain pulls 3.
        let first = q.drain(100, 10);
        assert_eq!(first.len(), 3);
        // Second drain 30 seconds later → no budget left.
        let second = q.drain(130, 10);
        assert!(second.is_empty(), "daily cap exhausted within 24h");
        // 25 hours later → budget reset.
        let later = q.drain(100 + 86_400 + 3_600, 10);
        assert_eq!(later.len(), 3, "budget reset after 24h rolls past");
    }

    #[test]
    fn drain_skips_items_scheduled_for_future() {
        let mut q = ProactiveQueue::new();
        q.enqueue(ProactiveItem {
            scheduled_for_unix: 1000,
            ..item(99, "future", "x")
        })
        .unwrap();
        q.enqueue(item(10, "now", "x")).unwrap();
        let drained = q.drain(500, 10);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].dedup_key, "now");
        // Future item still queued.
        assert_eq!(q.len(), 1);
        // Once the clock catches up, the future item drains.
        let later = q.drain(2000, 10);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].dedup_key, "future");
    }

    #[test]
    fn budget_left_reads_without_mutating_history() {
        let mut q = ProactiveQueue::new();
        assert_eq!(q.budget_left(100), 3);
        q.drained_at.push(50);
        assert_eq!(q.budget_left(100), 2);
        // Same call again — read-only.
        assert_eq!(q.budget_left(100), 2);
    }

    #[test]
    fn remove_by_key_returns_count_removed() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "stale", "x")).unwrap();
        q.enqueue(item(10, "fresh", "x")).unwrap();
        assert_eq!(q.remove_by_key("stale"), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.remove_by_key("missing"), 0);
    }

    #[test]
    fn old_egress_generation_never_removes_identical_reenqueue() {
        let mut queue = ProactiveQueue::new();
        assert!(queue.enqueue(item(50, "same", "source")).unwrap());
        let old_generation = queue.entry_generation("same").unwrap().to_string();
        queue.remove_by_key("same");
        assert!(queue.enqueue(item(50, "same", "source")).unwrap());
        let new_generation = queue.entry_generation("same").unwrap().to_string();
        assert_ne!(old_generation, new_generation);

        assert!(queue.settle_egress_once(
            &uuid::Uuid::now_v7().to_string(),
            "same",
            &old_generation,
            100,
        ));
        assert_eq!(queue.peek().len(), 1);
        assert_eq!(
            queue.entry_generation("same"),
            Some(new_generation.as_str())
        );
    }

    #[test]
    fn settlement_prunes_old_daily_budget_history() {
        let mut queue = ProactiveQueue::new();
        queue.drained_at.extend(0..10_000);
        queue.enqueue(item(50, "current", "source")).unwrap();
        let generation = queue.entry_generation("current").unwrap().to_string();
        assert!(queue.settle_egress_once("intent", "current", &generation, 200_000));
        assert_eq!(queue.drained_at, vec![200_000]);
    }

    #[test]
    fn legacy_queue_derives_a_stable_entry_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item(50, "legacy", "source")).unwrap();
        let mut value = serde_json::to_value(&queue).unwrap();
        value.as_object_mut().unwrap().remove("item_generations");
        crate::util::atomic_write::atomic_write_private(
            &path,
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        let first = ProactiveQueue::load_from(&path).unwrap();
        let second = ProactiveQueue::load_from(&path).unwrap();
        assert_eq!(
            first.entry_generation("legacy"),
            second.entry_generation("legacy")
        );
    }

    #[test]
    fn duplicate_dedup_keys_in_parseable_queue_quarantine_the_later_item() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proactive_queue.json");
        let value = serde_json::json!({
            "items": [item(50, "duplicate", "source-a"), item(10, "duplicate", "source-b")],
            "drained_at": [],
            "config": { "max_per_day": 3 },
            "settled_egress_intents": [],
            "item_generations": { "duplicate": "ambiguous-generation" }
        });
        crate::util::atomic_write::atomic_write_private(
            &path,
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        ProactiveQueue::modify(&path, |_| (false, ())).unwrap();
        let queue = ProactiveQueue::load_from(&path).unwrap();
        assert_eq!(queue.peek().len(), 1);
        assert_eq!(queue.peek()[0].source, "source-a", "first item wins");
        assert_eq!(queue.quarantined_items.len(), 1);
        assert_eq!(
            queue.quarantined_items[0].reason,
            ProactiveItemInvalidity::DuplicateDedupKey
        );
        let repaired_generation = queue.entry_generation("duplicate").unwrap().to_string();
        assert_ne!(repaired_generation, "ambiguous-generation");
        assert_eq!(
            ProactiveQueue::load_from(&path)
                .unwrap()
                .entry_generation("duplicate"),
            Some(repaired_generation.as_str()),
            "the repaired generation must remain stable after quarantine persistence"
        );
    }

    #[test]
    fn enqueue_enforces_exact_shared_item_bounds() {
        let mut queue = ProactiveQueue::new();
        assert_eq!(
            queue
                .enqueue(item(50, "", "source"))
                .unwrap_err()
                .root_cause()
                .to_string(),
            "proactive dedup key is empty"
        );
        assert!(
            queue
                .enqueue(item(
                    50,
                    &"x".repeat(MAX_PROACTIVE_DEDUP_KEY_BYTES + 1),
                    "source"
                ))
                .is_err()
        );
        assert!(
            queue
                .enqueue(ProactiveItem {
                    channel: "c".repeat(MAX_PROACTIVE_CHANNEL_BYTES + 1),
                    ..item(50, "channel-too-large", "source")
                })
                .is_err()
        );
        assert!(
            queue
                .enqueue(ProactiveItem {
                    source: "s".repeat(MAX_PROACTIVE_SOURCE_BYTES + 1),
                    ..item(50, "source-too-large", "replaced")
                })
                .is_err()
        );
        assert!(
            queue
                .enqueue(ProactiveItem {
                    body: "b".repeat(MAX_PROACTIVE_BODY_BYTES + 1),
                    ..item(50, "body-too-large", "source")
                })
                .is_err()
        );
        assert_eq!(
            queue
                .enqueue(ProactiveItem {
                    body: "\0".repeat(300_000),
                    ..item(50, "encoded-item-too-large", "source")
                })
                .unwrap_err()
                .root_cause()
                .to_string(),
            "serialized proactive item exceeds 1179648 bytes"
        );

        assert!(
            queue
                .enqueue(ProactiveItem {
                    dedup_key: "d".repeat(MAX_PROACTIVE_DEDUP_KEY_BYTES),
                    channel: "c".repeat(MAX_PROACTIVE_CHANNEL_BYTES),
                    source: "s".repeat(MAX_PROACTIVE_SOURCE_BYTES),
                    body: "b".repeat(MAX_PROACTIVE_BODY_BYTES),
                    ..item(50, "replaced", "source")
                })
                .unwrap()
        );
    }

    #[test]
    fn load_migration_quarantines_invalid_item_without_persisting_its_secrets() {
        for invalid in [
            ProactiveItem {
                dedup_key: String::new(),
                body: "dedup-secret".to_string(),
                ..item(50, "replaced", "source")
            },
            ProactiveItem {
                channel: format!("channel-secret-{}", "x".repeat(MAX_PROACTIVE_CHANNEL_BYTES)),
                body: "channel-body-secret".to_string(),
                ..item(50, "channel-invalid", "source")
            },
            ProactiveItem {
                source: format!("source-secret-{}", "x".repeat(MAX_PROACTIVE_SOURCE_BYTES)),
                body: "source-body-secret".to_string(),
                ..item(50, "source-invalid", "replaced")
            },
            ProactiveItem {
                body: format!("body-secret-{}", "x".repeat(MAX_PROACTIVE_BODY_BYTES)),
                ..item(50, "body-invalid", "source")
            },
            ProactiveItem {
                body: format!("encoded-secret-{}", "\0".repeat(300_000)),
                ..item(50, "encoded-invalid", "source")
            },
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("proactive_queue.json");
            let valid = item(50, "valid-successor", "source");
            let value = serde_json::json!({
                "items": [invalid.clone(), valid.clone()],
                "drained_at": [],
                "config": { "max_per_day": 3 },
                "settled_egress_intents": [],
                "item_generations": {}
            });
            crate::util::atomic_write::atomic_write_private(
                &path,
                &serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();

            ProactiveQueue::modify(&path, |_| (false, ())).unwrap();
            let migrated = ProactiveQueue::load_from(&path).unwrap();
            assert_eq!(migrated.peek(), std::slice::from_ref(&valid));
            assert_eq!(migrated.quarantined_items.len(), 1);
            assert!(migrated.entry_generation("valid-successor").is_some());

            let persisted = std::fs::read_to_string(&path).unwrap();
            assert!(!persisted.contains("dedup-secret"));
            assert!(!persisted.contains("channel-secret-"));
            assert!(!persisted.contains("channel-body-secret"));
            assert!(!persisted.contains("source-secret-"));
            assert!(!persisted.contains("source-body-secret"));
            assert!(!persisted.contains("body-secret-"));
            assert!(!persisted.contains("encoded-secret-"));
            assert!(persisted.contains("quarantined_items"));
        }
    }

    #[test]
    fn save_rejects_a_queue_that_the_next_load_would_reject() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proactive_queue.json");
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item(50, "baseline", "source")).unwrap();
        queue.save_to(&path).unwrap();
        let baseline = std::fs::read(&path).unwrap();

        for index in 0..16 {
            queue
                .enqueue(ProactiveItem {
                    body: "b".repeat(MAX_PROACTIVE_BODY_BYTES),
                    ..item(50, &format!("large-{index}"), "source")
                })
                .unwrap();
        }

        assert!(queue.save_to(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), baseline);
        assert_eq!(ProactiveQueue::load_from(&path).unwrap().peek().len(), 1);
    }

    #[test]
    fn save_then_load_round_trips_queue_plus_drain_history() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proactive.json");
        let mut q = ProactiveQueue::new();
        q.enqueue(item(50, "k1", "src1")).unwrap();
        q.enqueue(item(10, "k2", "src2")).unwrap();
        let drained = q.drain(1000, 1);
        assert_eq!(drained.len(), 1);
        q.save_to(&path).unwrap();

        let loaded = ProactiveQueue::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.peek()[0].dedup_key, "k2");
        // Drain history preserved — same-window subsequent load
        // still respects the cap.
        assert_eq!(loaded.budget_left(1000), 2);
    }

    #[test]
    fn load_from_returns_default_for_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never-existed.json");
        let q = ProactiveQueue::load_from(&path).unwrap();
        assert!(q.is_empty());
        assert_eq!(q.budget_left(0), 3);
    }

    #[cfg(windows)]
    #[test]
    fn load_from_migrates_a_broad_legacy_queue_dacl_through_the_bound_bridge() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy-proactive-queue.json");
        let encoded = serde_json::to_vec(&ProactiveQueue::default()).unwrap();
        std::fs::write(&path, &encoded).unwrap();
        crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(&path)
            .expect("seed a deliberately broad legacy queue DACL");
        assert!(crate::wal::win_native::verify_private_dacl(&path).is_err());

        let loaded = ProactiveQueue::load_from(&path)
            .expect("the bound bridge must migrate and durably read the legacy queue");

        assert!(loaded.is_empty());
        crate::wal::win_native::verify_private_dacl(&path)
            .expect("legacy queue DACL must satisfy the private contract after migration");
    }

    #[test]
    fn load_from_rejects_zero_length_published_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        crate::util::atomic_write::write_private_create_new(&path, b"").unwrap();
        assert!(ProactiveQueue::load_from(&path).is_err());
    }

    #[test]
    fn stats_carries_per_source_breakdown_and_budget() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "a", "g_01_mini")).unwrap();
        q.enqueue(item(10, "b", "g_01_mini")).unwrap();
        q.enqueue(item(10, "c", "pl_03")).unwrap();
        q.drain(500, 1);
        let s = q.stats(500);
        assert_eq!(s.queued, 2);
        assert_eq!(s.drained_last_24h, 1);
        assert_eq!(s.budget_left, 2);
        assert_eq!(s.by_source.get("g_01_mini").copied().unwrap_or(0), 1);
        assert_eq!(s.by_source.get("pl_03").copied().unwrap_or(0), 1);
    }

    #[test]
    fn operator_can_widen_cap_via_with_config() {
        let mut q = ProactiveQueue::with_config(ProactiveConfig { max_per_day: 10 });
        for i in 0..7 {
            q.enqueue(item(10, &format!("k{i}"), "x")).unwrap();
        }
        let drained = q.drain(1000, 99);
        assert_eq!(
            drained.len(),
            7,
            "with max_per_day=10 + cap=99, all 7 queued items drain",
        );
    }

    // ── Review H-1 — locked modify + reconcile commit ────────────────────────

    #[test]
    fn commit_drain_preserves_concurrent_enqueue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proactive_queue.json");

        // Tick loads a queue holding A+B and drains A in its working copy…
        let mut q = ProactiveQueue::new();
        q.enqueue(item(50, "a", "test")).unwrap();
        q.enqueue(item(50, "b", "test")).unwrap();
        q.save_to(&path).expect("seed save");

        // …while delivery runs, a producer lands C on disk…
        ProactiveQueue::modify(&path, |fresh| {
            let inserted = fresh.enqueue(item(50, "c", "test")).unwrap();
            (inserted, ())
        })
        .expect("producer enqueue");

        // …and the tick's save reconciles instead of blind-saving.
        ProactiveQueue::modify(&path, |fresh| {
            fresh.commit_drain(&["a".to_string()], 1, 1_800_000_000);
            (true, ())
        })
        .expect("commit");

        let after = ProactiveQueue::load_from(&path).expect("reload");
        let keys: Vec<&str> = after.peek().iter().map(|i| i.dedup_key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["b", "c"],
            "delivered A removed; concurrent C survives"
        );
        assert_eq!(
            after.budget_left(1_800_000_000),
            after.config.max_per_day - 1,
            "the drain budget entry survives the reconcile"
        );
    }

    #[test]
    fn prune_expired_drops_only_dead_items() {
        let mut q = ProactiveQueue::new();
        q.enqueue(ProactiveItem {
            expires_unix: 100,
            ..item(50, "dead", "test")
        })
        .unwrap();
        q.enqueue(ProactiveItem {
            expires_unix: 0,
            ..item(50, "evergreen", "test")
        })
        .unwrap();
        q.enqueue(ProactiveItem {
            expires_unix: 500,
            ..item(50, "alive", "test")
        })
        .unwrap();
        assert_eq!(q.prune_expired(200), 1);
        let keys: Vec<&str> = q.peek().iter().map(|i| i.dedup_key.as_str()).collect();
        assert_eq!(keys, vec!["evergreen", "alive"]);
    }
}
