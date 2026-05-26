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
    CronJobFired {
        job_id: String,
        ts_unix: i64,
    },
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
        let dbg = format!("{:?}", bus);
        assert!(dbg.contains("receiver_count"), "got: {dbg}");
        assert!(dbg.contains("EventBus"), "got: {dbg}");
    }
}
