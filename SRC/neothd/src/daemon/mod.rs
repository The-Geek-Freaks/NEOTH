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
pub mod export;
pub mod hardware;
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
