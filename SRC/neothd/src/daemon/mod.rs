//! Daemon-side utilities — PID file, future health endpoint, future
//! observability counters.
//!
//! Phase 33c blind-spot items live here. Keeping them out of the `cli/`
//! tree so the daemon-specific concerns stay distinct from operator-facing
//! command surfaces.

pub mod accelerator;
pub mod backup;
pub mod backup_retention;
pub mod clock_floor;
pub mod credentials_import_sidecar;
pub mod detect_complete_sidecar;
pub mod doctor_cron;
pub mod export;
pub mod hardware;
pub mod installer_audit_sidecar;
/// Round-3 v0.4 G-01 consumer half — periodic drain of
/// `proactive::ProactiveQueue` into a `proactive_delivered.jsonl`
/// sidecar. Operators tail the sidecar OR future channel adapters
/// subscribe to it for at-least-once delivery semantics. Ticks
/// every 5min (PROACTIVE_DRAIN_INTERVAL_SECS); per-tick cap
/// PROACTIVE_PER_TICK_CAP = 3 caps the notification storm even if
/// the queue's daily budget is wider.
pub mod proactive_dispatcher;
/// Round-3 v0.4 G-01 cron-wiring — periodic reflection-builder tick
/// that glues `reflection::build_reflection_item` (G-01-mini) +
/// `proactive::ProactiveQueue::enqueue` (G-01a). Ticks every 24h
/// (operator-tunable); the per-week dedup_key in the reflection
/// item itself keeps emissions to one per ISO week regardless of
/// tick frequency.
pub mod reflection_cron;
pub mod sidecar;
pub mod updater_cron;
// GC lives in `memory::gc` next to the SQLite tables it sweeps.
pub mod dreaming;
pub mod healthz;
pub mod isolation;
pub mod observability;
pub mod pidfile;
pub mod quota;
pub mod rate_limit;
pub mod usage_log;
// Telemetry static-enforcement lives at `tests/no_outbound_network.rs` —
// runs on every `cargo test` and blocks PRs. No daemon-side module needed.
