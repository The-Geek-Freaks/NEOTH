//! P-03 (Session 24) — Domain Event Bus.
//!
//! Council / sub_agents / cron currently reach into each other
//! directly: cron knows about council to schedule weekly reflection;
//! sub_agents knows about chat dispatch to gate sub-agent calls.
//! The transitive coupling makes adding a new consumer (e.g. the
//! upcoming Self-correction loop in v0.5 that wants to watch
//! provider responses) a multi-file change touching every producer.
//!
//! P-03 introduces a `tokio::sync::broadcast`-based bus + a
//! non-exhaustive [`DomainEvent`] enum so:
//!
//! - Producers fire one `bus.publish(event)` and don't care who's
//!   listening (or whether ANYONE is listening — lagged receivers
//!   degrade gracefully).
//! - Consumers `bus.subscribe()` and pattern-match on the variants
//!   they care about. Unknown variants don't break the consumer
//!   because the enum is `#[non_exhaustive]`.
//! - Adding a 5th event variant is back-compat: existing consumers
//!   compile because they have a `_ => {}` arm; new consumers can
//!   pattern-match on the new variant.
//!
//! ## Why broadcast + not mpsc
//!
//! Multiple consumers want each event (council + cron + audit). An
//! mpsc would force a single consumer to fan-out manually. Broadcast
//! gives every subscriber a copy. The trade-off: a slow consumer
//! triggers `RecvError::Lagged`; consumers MUST handle it (treat as
//! "missed N events" and keep going). The [`EventBus`] wrapper
//! documents the contract on the subscribe path.
//!
//! ## Not a WAL replacement
//!
//! Domain events are in-memory, ephemeral, fire-and-forget. They're
//! the right shape for "council just synthesised a verdict, anyone
//! who cares may want to react" — they're NOT the right shape for
//! audit. The audit chain stays in the WAL (`crate::wal::events`)
//! and the bus runs in addition. A producer that wants both fires
//! the WAL frame first (so the audit survives a crash) and the bus
//! event second (best-effort notification to live consumers).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Default channel buffer size. Tuned for "every event in the last
/// minute" — a 256-event buffer holds ~4 events/second of headroom
/// before lagged consumers start missing frames. Operators with
/// chat-heavy workloads can widen via [`EventBus::with_capacity`].
pub const DEFAULT_CAPACITY: usize = 256;

/// All the bus event variants. **Non-exhaustive on purpose**: adding
/// a new variant in a future version is back-compat for both
/// producers (they don't need to update) and consumers (they pattern-
/// match with a trailing `_ => {}` arm — the rust-patterns rule about
/// exhaustive matches is relaxed HERE precisely because the bus is a
/// pub-sub surface, not business logic).
///
/// Carry small, copy-able payloads. If a consumer needs the full
/// row, the variant should carry the id + the consumer reads back
/// from the canonical store (idx_episode / idx_profile / WAL). The
/// bus must not become a substitute database.
///
/// **Producer status (GOLD-WIRE-10):** only [`DomainEvent::ProviderResponded`]
/// currently has a producer — the council hemisphere path in `cli::chat`
/// publishes it, and the [`UsageMeter`] consumes it. The other four variants
/// are forward-infra with **no producer yet** (`CronJobFired` for the v0.5
/// scheduler, `CouncilWinnerSelected` / `SubAgentDispatched` for self-
/// correction, `WalFrameAppended` for live `wal tail`). The `#[non_exhaustive]`
/// enum is designed for exactly this incremental producer wiring — they are NOT
/// dead code to delete, but the bus is not a complete telemetry feed yet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainEvent {
    /// `council::resolve_*` finished + chose a winner. Payload:
    /// `winner_provider` slug + `synthesis_mode` label. Cron picks
    /// this up to decide whether to fire a follow-up reflection.
    CouncilWinnerSelected {
        winner_provider: String,
        synthesis_mode: String,
        ts_unix: i64,
    },
    /// A sub-agent (`@reviewer`, `@planner`, etc.) was dispatched.
    /// Audit consumers want this; the self-correction loop counts
    /// dispatches per minute for rate-limit telemetry.
    SubAgentDispatched {
        agent_name: String,
        operator_id: String,
        ts_unix: i64,
    },
    /// A cron job fired. The scheduler emits this AFTER the job
    /// command launched (not after it finished) so consumers see
    /// "scheduler is alive" beats independently of job latency.
    CronJobFired { job_id: String, ts_unix: i64 },
    /// A provider call returned a response. Self-correction loop in
    /// v0.5 subscribes; today only telemetry / metrics consume.
    ProviderResponded {
        provider: String,
        model: String,
        input_tokens: u32,
        output_tokens: u32,
        latency_ms: u32,
        ts_unix: i64,
    },
    /// A WAL frame was successfully appended. Pairs with the audit
    /// chain. Useful for live `neoth wal tail` dashboards without
    /// polling the segment file.
    WalFrameAppended {
        event_type: u8,
        event_id: u64,
        ts_unix: i64,
    },
}

impl DomainEvent {
    /// Stable wire-form discriminator. Used by the metrics surface
    /// to group event counts per variant + by tests as a drift
    /// guard for the `rename_all = "snake_case"` serde rename.
    pub fn kind(&self) -> &'static str {
        match self {
            DomainEvent::CouncilWinnerSelected { .. } => "council_winner_selected",
            DomainEvent::SubAgentDispatched { .. } => "sub_agent_dispatched",
            DomainEvent::CronJobFired { .. } => "cron_job_fired",
            DomainEvent::ProviderResponded { .. } => "provider_responded",
            DomainEvent::WalFrameAppended { .. } => "wal_frame_appended",
        }
    }
}

/// The bus. Cheaply clonable — every clone shares the same broadcast
/// channel. Subscribers get an independent [`broadcast::Receiver`]
/// with its own cursor.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<DomainEvent>,
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus")
            .field("receiver_count", &self.sender.receiver_count())
            .field("capacity", &self.sender.len())
            .finish()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl EventBus {
    /// New bus with the default capacity (256 events).
    pub fn new() -> Self {
        Self::default()
    }

    /// New bus with an explicit channel capacity. Slow consumers
    /// trigger `RecvError::Lagged(n)` when they fall this far behind.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }

    /// Publish one event. Returns the number of receivers that got
    /// a copy — `0` is NOT an error (no subscribers means no one
    /// cared). Pre-rule a future change to return `Err` on zero
    /// subscribers would be wrong: a producer firing into a quiet
    /// bus is fine.
    pub fn publish(&self, event: DomainEvent) -> usize {
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe + return a [`broadcast::Receiver`]. The receiver's
    /// cursor starts at the current bus position so a subscriber
    /// joining late doesn't replay history.
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }

    /// Live receiver count. Useful for diagnostics + the upcoming
    /// `neoth status` dashboard line.
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

// ── GOLD-WIRE-10: process-wide bus + the first real consumer (a meter) ────────

/// GOLD-WIRE-10 — live aggregate the daemon's meter-drainer task folds every
/// [`DomainEvent`] into. This is the KF-08 token-budget + activity meter: a
/// running total of provider tokens (the budget signal) + per-event counts.
/// Read it via [`global_meter`] (the `neoth gui-stream` budget poll + a future
/// `neoth doctor`/GUI surface consume the snapshot; the GUI display is WIRE-10b).
#[derive(Debug, Default)]
pub struct UsageMeter {
    events_total: AtomicU64,
    provider_responses: AtomicU64,
    input_tokens_total: AtomicU64,
    output_tokens_total: AtomicU64,
    /// Count of events the drainer DROPPED because it lagged > the bus
    /// capacity during a burst. Makes the best-effort undercount visible so a
    /// reader knows the token totals are a lower bound after `lagged_events > 0`.
    lagged_events: AtomicU64,
}

/// Copy-able read-out of [`UsageMeter`] for the poll/RPC surfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub events_total: u64,
    pub provider_responses: u64,
    pub input_tokens_total: u64,
    pub output_tokens_total: u64,
    /// Events dropped on drainer lag — when `> 0`, the token totals undercount.
    pub lagged_events: u64,
}

impl UsageMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one event into the running totals. Pure aside from the atomics, so
    /// it is unit-testable without the bus or a runtime.
    pub fn absorb(&self, ev: &DomainEvent) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        if let DomainEvent::ProviderResponded {
            input_tokens,
            output_tokens,
            ..
        } = ev
        {
            self.provider_responses.fetch_add(1, Ordering::Relaxed);
            self.input_tokens_total
                .fetch_add(u64::from(*input_tokens), Ordering::Relaxed);
            self.output_tokens_total
                .fetch_add(u64::from(*output_tokens), Ordering::Relaxed);
        }
    }

    /// Record `n` events the drainer dropped because it lagged the producer.
    pub fn record_lag(&self, n: u64) {
        self.lagged_events.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> UsageSnapshot {
        UsageSnapshot {
            events_total: self.events_total.load(Ordering::Relaxed),
            provider_responses: self.provider_responses.load(Ordering::Relaxed),
            input_tokens_total: self.input_tokens_total.load(Ordering::Relaxed),
            output_tokens_total: self.output_tokens_total.load(Ordering::Relaxed),
            lagged_events: self.lagged_events.load(Ordering::Relaxed),
        }
    }
}

static GLOBAL_BUS: OnceLock<EventBus> = OnceLock::new();
static GLOBAL_METER: OnceLock<Arc<UsageMeter>> = OnceLock::new();

/// GOLD-WIRE-10 — install the process-wide [`EventBus`] and spawn the meter
/// drainer task that folds every published event into the global [`UsageMeter`].
/// Returns `true` iff THIS call installed it (`false` if already installed).
/// Call at daemon boot (`run_serve`), inside a tokio runtime (it spawns the
/// drainer). The whole install runs inside `OnceLock::get_or_init`, so even
/// under concurrent callers the bus + meter + drainer are constructed EXACTLY
/// once (no TOCTOU, no orphan drainer, and the meter is installed before the
/// bus becomes visible). After this, producers fire [`publish`] and the meter
/// is read via [`global_meter_snapshot`].
pub fn init_global() -> bool {
    let mut installed = false;
    GLOBAL_BUS.get_or_init(|| {
        installed = true;
        let bus = EventBus::new();
        let meter = Arc::new(UsageMeter::new());
        let mut rx = bus.subscribe();
        let meter_for_task = Arc::clone(&meter);
        let meter_path = meter_snapshot_path();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        meter_for_task.absorb(&ev);
                        // GOLD-WIRE-10b: persist the live snapshot whenever a
                        // provider response lands, so the GUI / `neoth meter`
                        // subprocess can read it without sharing the bus.
                        if ev.kind() == "provider_responded"
                            && let Err(e) =
                                write_meter_snapshot(&meter_path, &meter_for_task.snapshot())
                        {
                            tracing::debug!(
                                error = %e,
                                path = %meter_path.display(),
                                "meter snapshot persist failed (best-effort)"
                            );
                        }
                    }
                    // A drainer that lagged behind a burst counts the dropped
                    // events (visible via `lagged_events`) and keeps going — the
                    // meter is best-effort telemetry, not an audit log.
                    Err(broadcast::error::RecvError::Lagged(n)) => meter_for_task.record_lag(n),
                    // The sender lives in GLOBAL_BUS forever, so Closed only
                    // happens at process teardown — end the task.
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        // Install the meter BEFORE returning the bus, so the moment GLOBAL_BUS is
        // visible the meter is already readable (no asymmetric window).
        let _ = GLOBAL_METER.set(meter);
        bus
    });
    installed
}

/// Publish to the process-wide bus. No-op (returns `0`) when the bus has not
/// been installed — one-shot CLIs that never call [`init_global`] still run.
/// Best-effort: a producer fires this and never blocks on subscribers.
pub fn publish(event: DomainEvent) -> usize {
    match GLOBAL_BUS.get() {
        Some(bus) => bus.publish(event),
        None => 0,
    }
}

/// The process-wide [`UsageMeter`] snapshot, when the bus is installed.
/// Returns `None` in one-shot CLI processes that never called [`init_global`]
/// (only `neoth serve` installs the bus). Callers MUST NOT treat `None` as a
/// zero budget — it means the meter is not installed in this process.
pub fn global_meter_snapshot() -> Option<UsageSnapshot> {
    GLOBAL_METER.get().map(|m| m.snapshot())
}

/// GOLD-WIRE-10b — canonical path where the daemon persists the live
/// `UsageSnapshot` so separate GUI / `neoth meter` processes can read it.
/// Matches the existing `neothd-gui` panel parser expectation
/// (`~/.neoth/usage_meter.json`).
pub fn meter_snapshot_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("usage_meter.json")
}

/// Atomically persist a snapshot to `path`. Writes to a temp file in the
/// same directory and renames, so a crash mid-write never leaves a
/// half-written JSON file. Errors are best-effort: the meter keeps running
/// even if the disk is temporarily unwritable.
pub fn write_meter_snapshot(path: &Path, snapshot: &UsageSnapshot) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(snapshot).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read the persisted meter snapshot, if any. Returns `None` when the file
/// is missing (daemon has never persisted) or unreadable.
pub fn read_meter_snapshot(path: &Path) -> Option<UsageSnapshot> {
    let body = std::fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(now: i64) -> DomainEvent {
        DomainEvent::CronJobFired {
            job_id: "morning-news".into(),
            ts_unix: now,
        }
    }

    #[test]
    fn kind_returns_canonical_snake_case_strings() {
        // Drift guard for the snake_case rename. A future refactor
        // that drops the serde attr would change how events
        // serialize but `kind()` would silently keep the old value.
        assert_eq!(
            DomainEvent::CronJobFired {
                job_id: "x".into(),
                ts_unix: 1
            }
            .kind(),
            "cron_job_fired",
        );
        assert_eq!(
            DomainEvent::CouncilWinnerSelected {
                winner_provider: "x".into(),
                synthesis_mode: "y".into(),
                ts_unix: 1,
            }
            .kind(),
            "council_winner_selected",
        );
        assert_eq!(
            DomainEvent::SubAgentDispatched {
                agent_name: "x".into(),
                operator_id: "y".into(),
                ts_unix: 1,
            }
            .kind(),
            "sub_agent_dispatched",
        );
        assert_eq!(
            DomainEvent::ProviderResponded {
                provider: "p".into(),
                model: "m".into(),
                input_tokens: 0,
                output_tokens: 0,
                latency_ms: 0,
                ts_unix: 1,
            }
            .kind(),
            "provider_responded",
        );
        assert_eq!(
            DomainEvent::WalFrameAppended {
                event_type: 0x01,
                event_id: 1,
                ts_unix: 1,
            }
            .kind(),
            "wal_frame_appended",
        );
    }

    #[test]
    fn serde_round_trip_uses_snake_case_kind_tag() {
        // Drift guard: the `#[serde(tag = "kind", rename_all =
        // "snake_case")]` tag MUST appear in the on-wire form.
        let event = DomainEvent::CronJobFired {
            job_id: "morning-news".into(),
            ts_unix: 1700,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"cron_job_fired\""), "got: {json}");
        let back: DomainEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn publish_into_empty_bus_returns_zero_not_error() {
        // No subscribers means no recipients — that's not a failure.
        // Pin this so a future refactor doesn't add `Result<usize>`.
        let bus = EventBus::new();
        let n = bus.publish(evt(1));
        assert_eq!(n, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_subscriber_receives_published_event() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let sent = evt(42);
        let count = bus.publish(sent.clone());
        assert_eq!(count, 1);
        let received = rx.recv().await.unwrap();
        assert_eq!(received, sent);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multiple_subscribers_each_get_a_copy() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        let mut rx3 = bus.subscribe();
        bus.publish(evt(99));
        for rx in [&mut rx1, &mut rx2, &mut rx3] {
            let e = rx.recv().await.unwrap();
            assert_eq!(
                e,
                DomainEvent::CronJobFired {
                    job_id: "morning-news".into(),
                    ts_unix: 99
                },
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscriber_joining_late_does_not_replay_history() {
        // Broadcast semantics: subscribers see events published
        // AFTER they subscribed. A late joiner shouldn't get the
        // backlog.
        let bus = EventBus::new();
        bus.publish(evt(1));
        bus.publish(evt(2));
        let mut late_rx = bus.subscribe();
        bus.publish(evt(3));
        let received = late_rx.recv().await.unwrap();
        match received {
            DomainEvent::CronJobFired { ts_unix, .. } => assert_eq!(ts_unix, 3),
            other => panic!("expected ts_unix=3, got {other:?}"),
        }
        // Channel should be empty (no second event waiting).
        assert!(late_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_consumer_gets_lagged_error_then_recovers() {
        // The lag contract operators need to handle. Pin via a tiny
        // capacity + flood-then-drain pattern.
        use tokio::sync::broadcast::error::TryRecvError;
        let bus = EventBus::with_capacity(2);
        let mut rx = bus.subscribe();
        for ts in 0..10 {
            bus.publish(evt(ts));
        }
        // First try_recv on a lagged channel returns Lagged(n) with
        // n = events skipped. After that, the cursor advances and
        // subsequent recvs work normally.
        let first = rx.try_recv();
        match first {
            Err(TryRecvError::Lagged(n)) => assert!(n > 0, "expected non-zero lag, got {n}"),
            other => panic!("expected Lagged, got {other:?}"),
        }
        // Recovery: next recv yields the OLDEST surviving event in
        // the buffer (capacity=2 → ts_unix=8 or 9).
        let next = rx.try_recv().unwrap();
        let ts = match next {
            DomainEvent::CronJobFired { ts_unix, .. } => ts_unix,
            other => panic!("unexpected variant: {other:?}"),
        };
        assert!(ts >= 8, "expected oldest-surviving ts ≥ 8, got {ts}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bus_clone_shares_the_same_channel() {
        // Cheap-clone contract: cloning the bus doesn't create a new
        // channel. A subscriber on the original sees events published
        // through the clone.
        let bus = EventBus::new();
        let bus2 = bus.clone();
        let mut rx = bus.subscribe();
        bus2.publish(evt(7));
        let e = rx.recv().await.unwrap();
        assert_eq!(
            e,
            DomainEvent::CronJobFired {
                job_id: "morning-news".into(),
                ts_unix: 7,
            },
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn receiver_count_reflects_live_subscribers() {
        let bus = EventBus::new();
        assert_eq!(bus.receiver_count(), 0);
        let rx1 = bus.subscribe();
        let rx2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);
        drop(rx1);
        assert_eq!(bus.receiver_count(), 1);
        drop(rx2);
        assert_eq!(bus.receiver_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capacity_min_one_even_when_caller_passes_zero() {
        // Defensive: tokio broadcast panics on capacity=0. The
        // wrapper clamps to ≥1 so a misconfigured operator doesn't
        // crash the daemon.
        let bus = EventBus::with_capacity(0);
        let mut rx = bus.subscribe();
        bus.publish(evt(1));
        let _ = rx.recv().await.unwrap();
    }

    #[test]
    fn debug_format_surfaces_receiver_count() {
        // Operator-visible drift guard: the Debug impl must show
        // receiver count so `dbg!(&bus)` is useful in a live shell.
        let bus = EventBus::new();
        let _rx = bus.subscribe();
        let dbg = format!("{bus:?}");
        assert!(dbg.contains("receiver_count"), "got: {dbg}");
        assert!(dbg.contains("EventBus"), "got: {dbg}");
    }

    // ── GOLD-WIRE-10: UsageMeter consumer ─────────────────────────────────

    fn provider_responded(input: u32, output: u32) -> DomainEvent {
        DomainEvent::ProviderResponded {
            provider: "claude_cli".into(),
            model: "claude-opus-4-8".into(),
            input_tokens: input,
            output_tokens: output,
            latency_ms: 1200,
            ts_unix: 1,
        }
    }

    #[test]
    fn usage_meter_absorbs_provider_tokens_and_counts_all_events() {
        let m = UsageMeter::new();
        m.absorb(&provider_responded(10, 5));
        m.absorb(&provider_responded(3, 7));
        // A non-provider event still bumps events_total but not the token totals.
        m.absorb(&evt(1));
        // A drainer lag drops 4 events — recorded so the undercount is visible.
        m.record_lag(4);
        let s = m.snapshot();
        assert_eq!(s.events_total, 3);
        assert_eq!(s.provider_responses, 2);
        assert_eq!(s.input_tokens_total, 13);
        assert_eq!(s.output_tokens_total, 12);
        assert_eq!(s.lagged_events, 4);
    }

    #[tokio::test]
    async fn producer_to_meter_consumer_end_to_end() {
        // The WIRE-10 contract: a producer publishes onto the bus, a subscribed
        // consumer (the meter) receives it and the token budget advances.
        // Driven with an explicit recv (no spawned task) so it is deterministic.
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let meter = UsageMeter::new();

        // Simulate a 3-hemisphere council call: 3 ProviderResponded events.
        assert_eq!(bus.publish(provider_responded(100, 40)), 1);
        bus.publish(provider_responded(80, 30));
        bus.publish(provider_responded(120, 50));

        for _ in 0..3 {
            let ev = rx.recv().await.expect("event delivered to subscriber");
            meter.absorb(&ev);
        }
        let s = meter.snapshot();
        assert_eq!(
            s.provider_responses, 3,
            "meter received every council hemisphere event"
        );
        assert_eq!(s.input_tokens_total, 300);
        assert_eq!(s.output_tokens_total, 120);
    }

    #[test]
    fn publish_is_noop_without_a_global_bus_in_a_oneshot_cli() {
        // A one-shot CLI never calls `init_global`; `publish` must not panic and
        // returns 0. (If another test in this binary installed the global bus,
        // the count may be >0 — so assert only the no-panic + non-negative
        // contract, not a hard 0.)
        let _ = publish(provider_responded(1, 1));
    }

    #[test]
    fn usage_snapshot_serde_roundtrips_for_the_poll_surface() {
        let s = UsageSnapshot {
            events_total: 9,
            provider_responses: 3,
            input_tokens_total: 300,
            output_tokens_total: 120,
            lagged_events: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: UsageSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[tokio::test]
    async fn global_drainer_folds_published_events_when_this_runtime_owns_it() {
        // Proves the REAL global path: publish() → GLOBAL_BUS → spawned drainer
        // → GLOBAL_METER. The drainer is tied to the runtime that FIRST called
        // init_global, so only assert the full drain when THIS test installed it
        // (idempotent return); otherwise just assert the bus is live. Whichever
        // test runs first in the binary exercises the full path.
        let we_installed = init_global();
        assert!(
            global_meter_snapshot().is_some(),
            "the meter must be installed after init_global"
        );
        if we_installed {
            let before = global_meter_snapshot().unwrap();
            publish(provider_responded(50, 20));
            publish(provider_responded(50, 20));
            // Let the spawned drainer task run (current-thread test runtime).
            for _ in 0..100 {
                tokio::task::yield_now().await;
                if global_meter_snapshot().unwrap().provider_responses
                    >= before.provider_responses + 2
                {
                    break;
                }
            }
            let after = global_meter_snapshot().unwrap();
            assert!(
                after.provider_responses >= before.provider_responses + 2,
                "the global drainer must fold published events into the meter \
                 (before={}, after={})",
                before.provider_responses,
                after.provider_responses
            );
            assert!(after.input_tokens_total >= before.input_tokens_total + 100);
        }
    }
}
