//! Daemon-side utilities — PID file, future health endpoint, future
//! observability counters.
//!
//! Phase 33c blind-spot items live here. Keeping them out of the `cli/`
//! tree so the daemon-specific concerns stay distinct from operator-facing
//! command surfaces.

pub mod accelerator;
/// GOLD-ADAPT-HERMES-09 — Lightweight token-throughput (TPS) meter for
/// provider streaming responses. [`metering::TpsMeter`] wraps a stream:
/// `start()` → repeated `observe(tokens)` → `finish()` → [`metering::TpsSample`].
/// [`metering::emit_tps_sample`] writes `0x69 TOKEN_TPS_SAMPLE` to the WAL.
/// The hot provider stream path is parallel-reserved; wiring the emit there
/// is a follow-up. Ships standalone with unit + WAL-integration tests.
pub mod metering;
/// GOLD-ADAPT-HERMES-03 — Mid-run clarification gate. When a worker hits an
/// ambiguity it calls [`clarify::ClarificationGate::park`], which parks the
/// run in `Waiting` state and surfaces a [`clarify::ClarificationRequest`].
/// An operator (or test) calls [`clarify::ClarificationGate::answer`] to
/// resume. Unambiguous inputs call [`clarify::ClarificationGate::pass_through`]
/// and see no state change. Self-contained, no hot-lane deps.
pub mod clarify;
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
/// NN-MEM-06 — daily contradiction auto-resolution cron. Processes the
/// `idx_contradictions` backlog: temporal-supersede (newer fact wins) +
/// semantic-equiv (Jaccard≥0.90 merge) + human-review queue for genuine
/// conflicts. Off by default (`contradiction_resolve.enabled = false`).
/// JV-SELF-02 — AMEM4Rec consolidation sweep cron. Clusters hot-tier
/// episode embeddings by cosine similarity, boosts importance, and merges
/// mature clusters into `idx_groundtruth`. Emits `0x9D`/`0x9E`. Off by
/// default (`consolidation_sweep.enabled = false`).
pub mod consolidation_sweep_cron;
/// JV-SELF-03 — auto-builder signal collector cron. Scans `idx_episode`
/// topic frequency, `idx_groundtruth` lessons, and the SkillOpt ledger
/// to classify improvement signals (`PatchSkill`, `PromptEdit`,
/// `ConfigChange`, `Escalate`). Writes `~/.neoth/self_improvement_signals.json`
/// atomically for HERMES-06. Emits `0xBE`/`0xBF`. Off by default
/// (`self_improvement_collector.enabled = false`).
pub mod self_improvement_collector;
pub mod contradiction_resolve_cron;
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
/// HO-07 — neoth-monitor alerting cron. Scans WAL integrity + crash.log +
/// channel activity every `monitor.interval_secs` and emits
/// `0x48 WAL_CRC_ALERT` / `0x49 CRASH_LOG_ALERT` /
/// `0x4A CHANNEL_SILENCE_ALERT` on anomalies. Off by default.
pub mod monitor_cron;
/// GOLD-ADAPT-HERMES-07b — log-analysis → patch-proposal → operator-reviewed
/// fix. Categorises panics from crash.log into staged, advisory PatchProposals
/// (never auto-applied). Consumed by the monitor crash path + `neoth self-heal`.
pub mod self_heal;
/// OM-01 — local OMI transcript ingest task. Polls a self-hosted OMI backend
/// (SC-14: cloud endpoints refused at startup), sanitises + promotes
/// high-confidence items to ground-truth (`0x9C`), extracts action items to
/// kanban. Off by default.
pub mod omi_ingest_task;
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
/// MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert cron. Reads the
/// `idx_recall_latency` window + emits `0x4B RECALL_LATENCY_ALERT` when p95
/// exceeds the threshold. Off by default.
pub mod recall_latency_cron;
/// Round-3 v0.4 G-01 cron-wiring — periodic reflection-builder tick
/// that glues `reflection::build_reflection_item` (G-01-mini) +
/// `proactive::ProactiveQueue::enqueue` (G-01a). Ticks every 24h
/// (operator-tunable); the per-week dedup_key in the reflection
/// item itself keeps emissions to one per ISO week regardless of
/// tick frequency.
pub mod reflection_cron;
/// ADV-14 — longitudinal recall-regression anchor cron. Weekly re-embeds the
/// anchor queries' fresh answers + emits `0x3F REGRESSION_ALERT` on cosine
/// drift below threshold. Off by default.
pub mod regression_cron;
pub mod resource_watch;
/// GOLD-ADAPT-VIEW-05 — session-health / outcome cron (A–F daily grade from the
/// WAL audit trail; alerts on degradation).
pub mod session_health_cron;
/// NN-MEM-02 — weekly 5-dimensional synthesis pattern-recognition cron. Reads
/// `idx_episode` (frequency + temporal-clustering), `idx_groundtruth`
/// (domain-correlation), and `idx_contradictions` (contradiction flags) to
/// produce a structured synthesis meta-note written as a `idx_groundtruth` row
/// (`source = "synthesis-cron"`, `scope = "meta"`) and optionally to
/// `~/.neoth/synthesis/YYYY-WW.md`. WAL-free; off by default
/// (`synthesis_cron.enabled = false`).
pub mod synthesis_cron;
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
/// GOLD-ADAPT-JV-PRO-02 — token-anomaly security tripwire cron (scans WAL usage
/// frames over a rolling baseline; emits `0x6E TOKEN_ANOMALY_DETECTED`).
pub mod token_anomaly_cron;
pub mod updater_cron;
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
// GC lives in `memory::gc` next to the SQLite tables it sweeps.
pub mod dreaming;
/// GOLD-ADAPT-JV-MEM-16 — Guidance-block snapshot refresh cron. Periodically
/// writes `~/.neoth/guidance_snapshot.json` (scorecard freshness + 24h WAL
/// signal counts) so `build_prompt_bundle` can inject richer session context
/// without re-scanning the WAL on every chat turn. WAL-free (reads only).
/// Off by default (`freedom.yaml::guidance_cron.enabled: true` to opt in).
pub mod guidance_cron;
pub mod healthz;
pub mod isolation;
pub mod observability;
pub mod pidfile;
pub mod quota;
pub mod rate_limit;
pub mod usage_log;
/// GOLD-ADAPT-ODY-07 — Background-job detach + auto-continue registry.
/// Tracks detached subprocess jobs via on-disk `.log`/`.exit` marker files.
/// Jobs register with [`bg_jobs::BgJobRegistry`]; the monitor polls for
/// completion and fires optional `on_complete` callbacks (auto-continue).
/// Self-contained, no hot-lane deps, new-file clean lane.
pub mod bg_jobs;
/// GOLD-ADAPT-GRAPH-05 — NEOTH self-map cron. Runs `graphify update` on the
/// daemon source tree on a schedule, copies `GRAPH_REPORT.md` +
/// `GRAPH_TREE.html` into `<vault>/NEOTH-Self/`, ingests the report into
/// `idx_groundtruth` (scope `neoth-self-map`), and emits `0xFB
/// SELF_MAP_COMPLETE`. Gated by `freedom.yaml::obsidian_vault` +
/// `self_map_source_dir` (or env `NEOTH_SRC_DIR`). Off by default.
pub mod self_map_task;
/// GOLD-ADAPT-ODY-07 companion — background-job monitor loop.
/// [`bg_monitor::spawn_bg_monitor`] spawns a periodic scan over the
/// [`bg_jobs::BgJobRegistry`]: completed jobs get their callbacks invoked,
/// are removed from the registry, and produce a [`bg_monitor::JobCompleteReport`].
pub mod bg_monitor;
// Telemetry static-enforcement lives at `tests/no_outbound_network.rs` —
// runs on every `cargo test` and blocks PRs. No daemon-side module needed.
