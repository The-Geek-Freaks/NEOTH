//! Daemon-side utilities — PID file, future health endpoint, future
//! observability counters.
//!
//! Phase 33c blind-spot items live here. Keeping them out of the `cli/`
//! tree so the daemon-specific concerns stay distinct from operator-facing
//! command surfaces.

pub mod accelerator;
/// AUDIT-RPC-01 — loopback audit-RPC listener + client so one-shot CLIs can
/// forward audit frames to the WAL-owning daemon (bearer-auth, loopback-only,
/// event-type allowlist). Gated `freedom.yaml::audit_rpc.enabled` (default off).
pub mod audit_rpc;
/// MV-01b (Session 28c) — daemon CLI auto-apply loop. At
/// `AutonomyLevel::Elevated`/`Full` it periodically applies updates for
/// the NEOTH-managed CLIs (claude-cli / antigravity-cli / codex) and
/// emits `0x13 UPDATE_RAN`; notify-only below that tier.
pub mod auto_update;
pub mod backup;
pub mod backup_retention;
pub mod clock_floor;
pub mod credentials_import_sidecar;
pub mod detect_complete_sidecar;
pub mod doctor_cron;
/// HO-09b — profile drift-alert cron. Runs the same drift evaluation
/// as `neoth profile drift report` on a 6h schedule + emits a
/// `0xBA PROFILE_DRIFT_ALERT` WAL frame when drift strictly exceeds
/// `freedom.yaml::drift_alert.threshold`. Off by default (master
/// switch `drift_alert.enabled`).
pub mod drift_alert_cron;
pub mod export;
/// Round-3 v0.4 G-02 cron-wiring — daily tick that scans
/// `idx_profile` for novel high-confidence claims via
/// `profile::surfacing::find_novel_high_confidence_claims` +
/// renders each as a bilingual `ProactiveItem` for the G-01
/// drain → sidecar chain. Per-claim dedup_key in the item itself
/// caps re-enqueue noise; the cron just stays out of the LLM
/// extractor's way (Stage 3 deferred).
pub mod g02_surfacing_cron;
pub mod hardware;
pub mod installer_audit_sidecar;
pub mod model_download_audit;
/// G-01 (first slice) — inactivity-gap detector: enqueues one proactive
/// "still there?" nudge after `pattern_cron.inactivity_gap_secs` of
/// operator silence (deduped per UTC day), onto the G-01 proactive
/// substrate. Off by default. The first detector of the named
/// pattern-detection cron; further detectors layer on the same shape.
pub mod pattern_cron;
/// Round-3 v0.4 G-01 consumer half — periodic drain of
/// `proactive::ProactiveQueue` into a `proactive_delivered.jsonl`
/// sidecar. Operators tail the sidecar OR future channel adapters
/// subscribe to it for at-least-once delivery semantics. Ticks
/// every 5min (PROACTIVE_DRAIN_INTERVAL_SECS); per-tick cap
/// PROACTIVE_PER_TICK_CAP = 3 caps the notification storm even if
/// the queue's daily budget is wider.
pub mod proactive_dispatcher;
pub mod profile_adapt_cron;
/// Round-3 v0.4 G-01 cron-wiring — periodic reflection-builder tick
/// that glues `reflection::build_reflection_item` (G-01-mini) +
/// `proactive::ProactiveQueue::enqueue` (G-01a). Ticks every 24h
/// (operator-tunable); the per-week dedup_key in the reflection
/// item itself keeps emissions to one per ISO week regardless of
/// tick frequency.
pub mod reflection_cron;
pub mod resource_watch;
/// HO-07 — neoth-monitor alerting cron. Scans WAL integrity + crash.log +
/// channel activity every `monitor.interval_secs` and emits
/// `0x48 WAL_CRC_ALERT` / `0x49 CRASH_LOG_ALERT` /
/// `0x4A CHANNEL_SILENCE_ALERT` on anomalies. Off by default.
pub mod monitor_cron;
/// GOLD-FEAT-09 — daemon watchdog/auto-recovery cron. Probes supervised local
/// services (n8n / Ollama) every `watchdog.interval_secs`, restarts them at
/// `Elevated`+ autonomy after `consecutive_failures_before_restart` down ticks
/// (crash-loop-guarded by a per-window restart budget), and emits
/// `0x5F WATCHDOG_RESTART`. Off by default.
pub mod watchdog_cron;
/// MONITOR-02 — real-time worker-task death detection. Polls the daemon's
/// long-running cron/worker abort handles + emits `0x4D WORKER_DIED` (naming the
/// task) the moment one panics/exits — lower latency + attribution than the
/// HO-07 crash.log scan. Holds only abort-handle clones (shutdown unaffected).
pub mod worker_watch;
/// OM-01 — local OMI transcript ingest task. Polls a self-hosted OMI backend
/// (SC-14: cloud endpoints refused at startup), sanitises + promotes
/// high-confidence items to ground-truth (`0x9C`), extracts action items to
/// kanban. Off by default.
pub mod omi_ingest_task;
/// ADV-14 — longitudinal recall-regression anchor cron. Weekly re-embeds the
/// anchor queries' fresh answers + emits `0x3F REGRESSION_ALERT` on cosine
/// drift below threshold. Off by default.
pub mod regression_cron;
/// MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert cron. Reads the
/// `idx_recall_latency` window + emits `0x4B RECALL_LATENCY_ALERT` when p95
/// exceeds the threshold. Off by default.
pub mod recall_latency_cron;
pub mod sidecar;
pub mod skill_forge;
/// HO-06 (Session 28) — credential-pattern scanner that walks
/// operator-listed paths at daemon boot for `ghp_` / `sk-` / `AKIA`
/// shapes (re-uses `security::redact::PATTERNS`). Optional git
/// remote URL check for inline `user:token@host` patterns. Warn-
/// only — never fails boot on a finding (operators legitimately
/// keep API keys in shell rc files).
pub mod startup_credential_audit;
/// MV-01b prereq #3 — OS-native process-supervisor install (systemd
/// user unit / launchd LaunchAgent / Windows Task Scheduler) so the
/// daemon auto-restarts + unattended self-update can activate the new
/// binary. User-scoped, no root/admin.
pub mod supervisor;
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
