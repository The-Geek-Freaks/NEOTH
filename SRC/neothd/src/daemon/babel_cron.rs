//! GOLD-DELTA-04 — Babel observer daemon cron.
//!
//! Async wrapper around the pure tick logic in `analytics/babel/cron.rs`:
//! every `babel.tick_interval_secs` the loop
//!
//! 1. scans the WAL segments for frames appended since the last tick
//!    (in-memory per-segment logical-offset cursor, initialised to the
//!    segment ends at spawn — the observer watches runtime behaviour from
//!    boot; it does not backfill history),
//! 2. maps each frame onto content-free [`WalEventRecord`]s (the payloads
//!    NEOTH writes to the WAL are already content-free — hashes, counts,
//!    ids — the mapper only projects them),
//! 3. runs [`BabelCronState::tick`] under the views.db writer lock,
//! 4. logs every 15-min threshold breach via `tracing::warn!` (no WAL
//!    event — the byte space is exhausted, 255/256).
//!
//! ## Mapping notes
//!
//! - **K_d**: the WAL never carries response text. The in-process bounded
//!   feed reduces each final response at its source to either the original
//!   K_d_v0 histogram or a local K_d_embed_v1 vector; raw text is never
//!   persisted or federated.
//! - **Retry**: NEOTH has no retry WAL event; a repeat of the identical
//!   `(server::tool, arguments_hash)` MCP call within 120 s is synthesised
//!   as a Retry (the `arguments_hash` makes this precise, not fuzzy).
//! - **FallbackResult**: 0x25 records the attempt only; a
//!   `PROVIDER_RESPONSE` within 120 s of a pending attempt is synthesised
//!   as `FallbackResult { success: true }` — no response in the horizon
//!   leaves the attempt dangling, which is exactly what the
//!   `fallback_failure` detector wants to see.
//! - **D_d**: no schema-conflict WAL source exists (0xC1 is the
//!   allowlist/permission rejection, not a schema conflict) → D stays at
//!   its neutral 1.0 in v0.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::analytics::babel::anonymize;
use crate::analytics::babel::config::BabelConfig;
use crate::analytics::babel::cron::{BabelCronState, CronEvent, WalEventKind, WalEventRecord};
use crate::analytics::babel::store;
use crate::analytics::babel::window::WindowGranularity;
use crate::coding::feed::FeedEntry;
use crate::memory::store::ViewsExecutor;
use crate::permissions::AutonomyLevel;
use crate::wal::events::{
    EVENT_TYPE_AGENT_DISPATCHED, EVENT_TYPE_BUDGET_EXCEEDED, EVENT_TYPE_CONTEXT_COMPACTION_START,
    EVENT_TYPE_MCP_TOOL_CALLED, EVENT_TYPE_PROVIDER_ERROR, EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
    EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_RESOURCE_PRESSURE_ALERT,
};

/// Repeat/correlation horizon for the synthesised Retry and FallbackResult
/// events (seconds).
const SYNTH_HORIZON_SECS: i64 = 120;

/// GOLD-DELTA-05 — cadence of the p1/p99 norm-table refresh.
const NORM_SWEEP_SECS: i64 = 300;

/// GOLD-DELTA-11 — push operator-relevant Babel events onto the kanban SSE
/// feed: every PRIMARY (15-min) window close plus every threshold breach.
/// 5-min windows stay off the feed — four lines an hour is signal, twelve
/// is noise. `event_type = 0x00` marks "no WAL correlate" (the Babel
/// subsystem is SQLite-only; the byte space is exhausted). Returns the
/// number of lines published. A send error just means no subscriber is
/// connected — normal, not a failure.
fn publish_sse(
    sse: &tokio::sync::broadcast::Sender<FeedEntry>,
    events: &[CronEvent],
    now_ns: u64,
) -> usize {
    let mut published = 0usize;
    for ev in events {
        let message = match ev {
            CronEvent::WindowComputed(w) if w.granularity == WindowGranularity::FifteenMin => {
                let b_log = w
                    .scores
                    .b_log
                    .map(|b| format!("{b:.4}"))
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    "babel window {}s closed: b_log={} b_bottleneck={:.4} collapse_5m={}",
                    w.granularity.secs(),
                    b_log,
                    w.scores.b_bottleneck,
                    if w.collapse.collapse_within_5m { 1 } else { 0 },
                )
            }
            CronEvent::ThresholdBreached {
                window_id,
                score,
                threshold,
            } => format!(
                "babel THRESHOLD BREACH on 15-min window {window_id}: b_mult {score:.4} >= {threshold:.4}"
            ),
            CronEvent::WindowComputed(_) => continue,
        };
        let entry = FeedEntry {
            ts_ns: now_ns,
            event_type: 0x00,
            actor: "babel".to_string(),
            message,
        };
        if sse.send(entry).is_ok() {
            published += 1;
        }
    }
    published
}

/// AutonomyLevel → A_d normalisation scalar (`feature.rs` A_d_v0:
/// Strict=1, Standard=2, Elevated=3, Full=4). Custom has no fixed agent
/// density expectation — treated as Standard.
fn autonomy_scalar(level: AutonomyLevel) -> u8 {
    match level {
        AutonomyLevel::Strict => 1,
        AutonomyLevel::Standard | AutonomyLevel::Custom => 2,
        AutonomyLevel::Elevated => 3,
        AutonomyLevel::Full => 4,
    }
}

/// Derive the privacy-preserving provider/family value carried by federated
/// windows from the same provider configuration used by inference.
fn configured_primary_model_family(config: Option<&crate::config::FreedomConfig>) -> String {
    let Some(config) = config else {
        return "unknown".to_string();
    };
    let Some(provider) = config.provider_kind else {
        return "unknown".to_string();
    };
    let model = config
        .provider_model
        .as_deref()
        .map(|id| config.resolve_model_alias(id))
        .unwrap_or("default");
    anonymize::coarsen_model(provider.as_provider_id(), model)
}

/// Mapper state for the synthesised events (see module doc).
#[derive(Default)]
struct MapperState {
    /// `(server::tool, arguments_hash)` → last seen ts. A repeat within
    /// [`SYNTH_HORIZON_SECS`] is a Retry.
    recent_tool_calls: HashMap<(String, String), i64>,
    /// Pending fallback `(route, attempt_ts)` awaiting a provider response.
    pending_fallback: Option<(String, i64)>,
}

impl MapperState {
    /// Drop repeat-tracking entries older than the synthesis horizon.
    fn prune(&mut self, now: i64) {
        self.recent_tool_calls
            .retain(|_, ts| now - *ts <= SYNTH_HORIZON_SECS);
        if let Some((_, ts)) = &self.pending_fallback {
            if now - *ts > SYNTH_HORIZON_SECS {
                self.pending_fallback = None;
            }
        }
    }
}

/// Map one decoded WAL frame onto zero or more Babel events.
fn map_frame(
    event_type: u8,
    header_ts_unix: i64,
    payload: &[u8],
    mapper: &mut MapperState,
) -> Vec<WalEventRecord> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Vec::new(); // non-JSON payloads carry nothing we consume
    };
    let ts = v
        .get("ts_unix")
        .and_then(|t| t.as_i64())
        .unwrap_or(header_ts_unix);
    let mut out = Vec::new();
    match event_type {
        EVENT_TYPE_MCP_TOOL_CALLED => {
            let server = v.get("server_id").and_then(|s| s.as_str()).unwrap_or("?");
            let tool_name = v.get("tool").and_then(|s| s.as_str()).unwrap_or("?");
            let tool = format!("{server}::{tool_name}");
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::McpToolCalled {
                    tool: tool.clone(),
                    agent_id: None,
                },
            });
            if v.get("is_error").and_then(|b| b.as_bool()).unwrap_or(false) {
                out.push(WalEventRecord {
                    ts_unix: ts,
                    kind: WalEventKind::ToolError {
                        tool: Some(tool.clone()),
                        error_kind: None,
                    },
                });
            }
            if let Some(hash) = v.get("arguments_hash").and_then(|s| s.as_str()) {
                let key = (tool.clone(), hash.to_string());
                if let Some(prev) = mapper.recent_tool_calls.get(&key) {
                    if ts - prev <= SYNTH_HORIZON_SECS {
                        out.push(WalEventRecord {
                            ts_unix: ts,
                            kind: WalEventKind::Retry {
                                tool: Some(tool),
                                agent_id: None,
                            },
                        });
                    }
                }
                mapper.recent_tool_calls.insert(key, ts);
            }
        }
        EVENT_TYPE_AGENT_DISPATCHED => {
            if let Some(name) = v.get("agent_name").and_then(|s| s.as_str()) {
                out.push(WalEventRecord {
                    ts_unix: ts,
                    kind: WalEventKind::AgentDispatched {
                        agent_id: name.to_string(),
                    },
                });
            }
        }
        EVENT_TYPE_PROVIDER_RESPONSE => {
            let output_tokens = v.get("output_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::LlmResponse {
                    output_tokens,
                    // K_d histograms cannot come from the WAL (module doc).
                    token_histogram: HashMap::new(),
                    context_used_ratio: None,
                },
            });
            if let Some((route, attempt_ts)) = mapper.pending_fallback.take() {
                if ts - attempt_ts <= SYNTH_HORIZON_SECS {
                    out.push(WalEventRecord {
                        ts_unix: ts,
                        kind: WalEventKind::FallbackResult {
                            route,
                            success: true,
                        },
                    });
                }
            }
        }
        EVENT_TYPE_PROVIDER_ERROR => {
            let error_kind = v.get("error").and_then(|s| s.as_str()).map(str::to_string);
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::InferenceEnd { error_kind },
            });
        }
        EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED => {
            let route = format!(
                "{}:hop{}",
                v.get("to_provider").and_then(|s| s.as_str()).unwrap_or("?"),
                v.get("hop").and_then(|h| h.as_u64()).unwrap_or(0),
            );
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::FallbackAttempt {
                    route: route.clone(),
                },
            });
            mapper.pending_fallback = Some((route, ts));
        }
        EVENT_TYPE_BUDGET_EXCEEDED => {
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::ResourceSnapshot {
                    vram_pct: None,
                    budget_consumed_ratio: Some(1.0),
                },
            });
        }
        EVENT_TYPE_RESOURCE_PRESSURE_ALERT => {
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::ResourceSnapshot {
                    vram_pct: v.get("pct").and_then(|p| p.as_f64()),
                    budget_consumed_ratio: None,
                },
            });
        }
        EVENT_TYPE_CONTEXT_COMPACTION_START => {
            // Compaction fires at the context-pressure threshold; 0.95 is the
            // documented proxy ratio (payload carries token counts, not the
            // model's true window size).
            out.push(WalEventRecord {
                ts_unix: ts,
                kind: WalEventKind::ContextBoundary {
                    context_used_ratio: 0.95,
                },
            });
        }
        _ => {}
    }
    mapper.prune(ts);
    out
}

/// Per-segment scan cursor: `next_logical` is the next LOGICAL
/// (decompressed) frame offset to process; `physical_len` is the file size
/// at the last scan — a shrink means the segment was rewritten (truncation /
/// compaction) and the logical cursor is void.
#[derive(Clone, Copy, Default)]
struct SegmentCursor {
    next_logical: usize,
    physical_len: usize,
}

/// Per-segment cursors + mapper state, moved in and out of
/// `spawn_blocking` each tick.
#[derive(Default)]
struct ScanState {
    offsets: HashMap<PathBuf, SegmentCursor>,
    mapper: MapperState,
}

impl ScanState {
    /// Walk every `*.wal` segment in name order (numbered segments sort
    /// chronologically — `read_dir` order is arbitrary and would break the
    /// cross-segment retry/fallback correlation), process frames at/after
    /// the saved cursor, advance the cursor. `emit = false` records offsets
    /// without producing events (the spawn-time fast-forward). Unreadable or
    /// tamper-suspect segments are warned about and skipped — the cursor
    /// does not advance past a decode failure, so a transient read glitch is
    /// retried next tick. A segment whose file SHRANK was rewritten — its
    /// logical cursor is reset (one-time re-emit beats a silently frozen
    /// observer). Cursors of deleted segments are dropped.
    fn scan(&mut self, wal_dir: &Path, emit: bool) -> Vec<WalEventRecord> {
        let mut events = Vec::new();
        let Ok(rd) = std::fs::read_dir(wal_dir) else {
            return events;
        };
        let mut seg_paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect();
        seg_paths.sort();
        for p in seg_paths {
            let Ok(bytes) = std::fs::read(&p) else {
                tracing::warn!(segment = %p.display(), "babel scan: segment unreadable, skipped");
                // Drop the cursor: if the segment gets rewritten while
                // unreadable, a stale physical_len would hide the shrink and
                // frames below the old offset would be lost forever. A
                // one-time re-emit after recovery is the cheaper failure.
                self.offsets.remove(&p);
                continue;
            };
            let saved = self.offsets.get(&p).copied().unwrap_or_default();
            let start = if bytes.len() < saved.physical_len {
                tracing::warn!(
                    segment = %p.display(),
                    prev_len = saved.physical_len,
                    len = bytes.len(),
                    "babel scan: segment shrank (rewrite/truncation); cursor reset"
                );
                0
            } else {
                saved.next_logical
            };
            let mut next = start;
            let mapper = &mut self.mapper;
            let walk = crate::wal::scan::for_each_frame(&bytes, |cursor, dec| {
                let advance = cursor + dec.header.total_len as usize;
                if cursor >= start {
                    if emit {
                        let header_ts = (dec.header.hlc.physical_ns() / 1_000_000_000) as i64;
                        events.extend(map_frame(
                            dec.header.event_type,
                            header_ts,
                            dec.payload,
                            mapper,
                        ));
                    }
                    next = next.max(advance);
                }
                Ok(())
            });
            if let Err(e) = walk {
                tracing::warn!(segment = %p.display(), error = %e, "babel scan: segment walk aborted");
            }
            self.offsets.insert(
                p,
                SegmentCursor {
                    next_logical: next,
                    physical_len: bytes.len(),
                },
            );
        }
        // Rotated-away segments never come back — drop their cursors.
        self.offsets.retain(|p, _| p.exists());
        events
    }
}

/// Spawn the Babel observer loop. Returns `None` when `babel.enabled ==
/// false` — no idle tokio task. Mirrors
/// [`super::monitor_cron::spawn_monitor_cron_loop`].
pub fn spawn_babel_cron_loop(
    mut cfg: BabelConfig,
    autonomy: AutonomyLevel,
    home: PathBuf,
    wal_dir: PathBuf,
    views: Arc<ViewsExecutor>,
    sse: Option<Arc<tokio::sync::broadcast::Sender<FeedEntry>>>,
    provider_config: Option<crate::config::FreedomConfig>,
) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        tracing::info!("babel observer disabled (babel.enabled = false)");
        return None;
    }
    // Floor of 1s: protects against a zero interval (busy loop) while
    // keeping 1s ticks available for integration tests.
    let interval_secs = cfg.tick_interval_secs.max(1);
    Some(tokio::spawn(async move {
        if let Err(e) = views.with_writer(store::ensure_schema).await {
            tracing::error!(error = %e, "babel: schema init failed; observer not started");
            return;
        }
        // Session identity: HMAC-pseudonymised boot id, keyed on the WAL HMAC
        // master key (stable per install, one-way). Key load failure falls
        // back to a boot-random salt — still pseudonymous, just not stable
        // across restarts.
        let salt = crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key"))
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "babel: WAL hmac key unavailable, using boot-random salt");
                uuid::Uuid::now_v7().into_bytes().to_vec()
            });
        let boot_id = uuid::Uuid::now_v7().to_string();
        let session_pseudo = anonymize::pseudonymise_id(&salt, &boot_id);
        // Total tools available (C_d denominator): pinned allowlist entries
        // across configured MCP servers. Servers without a pin contribute 0 —
        // the accumulator clamps the denominator to >= 1.
        let mcp_tool_count: usize = match crate::mcp::config::McpServers::load() {
            Ok(f) => f
                .servers
                .iter()
                .map(|s| s.allow_tools.as_ref().map_or(0, Vec::len))
                .sum(),
            Err(e) => {
                // total=0 clamps the C_d denominator to 1 and inflates
                // coupling — make the degraded metric traceable.
                tracing::warn!(error = %e, "babel: MCP config unreadable; C_d denominator degraded to 1");
                0
            }
        };
        let mut state = BabelCronState::new(
            &cfg,
            session_pseudo,
            autonomy_scalar(autonomy),
            crate::time::now_unix_i64(),
            mcp_tool_count,
        );
        // Fast-forward the cursors to the current segment ends: observe from
        // boot, never backfill (old events in a fresh window would be noise).
        let wd = wal_dir.clone();
        let mut scan = match tokio::task::spawn_blocking(move || {
            let mut s = ScanState::default();
            s.scan(&wd, false);
            s
        })
        .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "babel: cursor init task failed; observer not started");
                return;
            }
        };
        // GOLD-DELTA-10 — federation prerequisites, prepared once. The
        // signing key doubles as the batch-signature identity; a load
        // failure disables federation for this run (warned once below).
        let federation_signing_key = crate::wal::signing::load_or_init_signing_key(
            &crate::wal::signing::default_signing_key_path(),
        )
        .ok();
        let primary_model_family = configured_primary_model_family(provider_config.as_ref());
        let federation_meta = crate::analytics::babel::anonymize::SubmissionMetadata {
            contributor_id: crate::analytics::babel::anonymize::derive_contributor_id(
                &salt,
                "The-Geek-Freaks/NEOTH",
            ),
            deployment_context: crate::analytics::babel::anonymize::DeploymentContext::SingleUser,
            hardware_tier: crate::analytics::babel::anonymize::HardwareTier::Workstation,
            primary_model_family,
            avg_tasks_per_day_bucket: 0,
            protocol_version:
                crate::analytics::babel::anonymize::SubmissionMetadata::PROTOCOL_VERSION,
            runtime_class: crate::analytics::babel::anonymize::SubmissionMetadata::RUNTIME_CLASS,
        };
        let pending_dir = home.join("babel").join("pending");
        // Panel decision Q3 (2026-07-02): the consent prompt fires ONCE per
        // boot, the first time the gate preconditions all hold while
        // federate is still off — informed consent at calibration maturity.
        let mut federation_prompted = false;
        // GOLD-DELTA-14 — pooled predictor state: pull at most once per day,
        // log the advisory once per boot (cache gives day-1 coverage).
        #[cfg(feature = "cluster-iroh")]
        let mut last_predictor_pull: i64 = 0;
        #[cfg(feature = "cluster-iroh")]
        const PREDICTOR_PULL_SECS: i64 = 86_400;
        let mut predictor_advisory_logged = false;

        // GOLD-DELTA-16 — live K_d feed from the inference paths. The default
        // is the exact v0 histogram; an explicit local model selects v1
        // embeddings without relabelling histogram data.
        let k_d_embed_provider = if let Some(model) = cfg.k_d_embedding_model.clone() {
            match provider_config {
                Some(mut provider_config) => {
                    // Select real weights through the existing local provider
                    // factory; EmbedRequest::model alone is only an identity
                    // field on current adapters and must not relabel another
                    // checkpoint's vectors.
                    provider_config.provider_model = Some(model);
                    crate::providers::embed_provider_from_config(&provider_config).await
                }
                None => None,
            }
        } else {
            None
        };
        let k_mode = match cfg.k_d_embedding_model.clone() {
            Some(requested_model) => {
                if k_d_embed_provider.is_none() {
                    tracing::warn!(
                        model = %requested_model,
                        "babel: K_d embedding requested but no configured local EmbedProvider is available; windows degrade deterministically"
                    );
                }
                crate::analytics::babel::khist::KdFeedMode::EmbeddingV1 {
                    requested_model,
                    provider: k_d_embed_provider,
                }
            }
            None => crate::analytics::babel::khist::KdFeedMode::HistogramV0,
        };
        let mut khist_rx = crate::analytics::babel::khist::register(1024, k_mode);
        let mut signal_rx =
            crate::analytics::babel::signals::register(cfg.memory_signals, cfg.skill_signals, 1024);
        tracing::info!(
            interval_secs,
            threshold = cfg.threshold,
            "babel observer cron online (GOLD-DELTA-04)"
        );
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_norm_sweep: i64 = 0;
        // GOLD-DELTA-15 — only windows stamped after boot feed the online
        // threshold calibration (the adjustment is path-dependent; replaying
        // history after every restart would double-count it).
        let mut calibration_cursor_ts: i64 = crate::time::now_unix_i64();
        loop {
            ticker.tick().await;
            let wd = wal_dir.clone();
            let (mut events, returned) = match tokio::task::spawn_blocking(move || {
                let ev = scan.scan(&wd, true);
                (ev, scan)
            })
            .await
            {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!(error = %e, "babel: scan task panicked; observer stopping");
                    return;
                }
            };
            scan = returned;
            // GOLD-DELTA-16 — merge live K_d histograms into this tick's
            // event stream (token counts stay WAL-sourced: output_tokens 0
            // here avoids double-counting V_d).
            while let Ok(sample) = khist_rx.try_recv() {
                let kind = match sample.value {
                    crate::analytics::babel::khist::KSampleValue::Histogram(token_histogram) => {
                        WalEventKind::LlmResponse {
                            output_tokens: 0,
                            token_histogram,
                            context_used_ratio: None,
                        }
                    }
                    crate::analytics::babel::khist::KSampleValue::Embedding {
                        vector,
                        model_identity,
                    } => WalEventKind::LlmEmbedding {
                        vector,
                        model_identity,
                    },
                    crate::analytics::babel::khist::KSampleValue::EmbeddingFailure {
                        model_identity,
                        reason,
                    } => WalEventKind::LlmEmbeddingFailure {
                        model_identity,
                        reason,
                    },
                };
                events.push(WalEventRecord {
                    ts_unix: sample.ts_unix,
                    kind,
                });
            }
            while let Ok(sample) = signal_rx.try_recv() {
                events.push(WalEventRecord {
                    ts_unix: sample.ts_unix,
                    kind: WalEventKind::AuxSignal(sample.kind),
                });
            }
            let now = crate::time::now_unix_i64();
            let tick_result = views
                .with_writer(|conn| state.tick(now, events, mcp_tool_count, conn))
                .await;
            match tick_result {
                Ok(out) => {
                    // GOLD-DELTA-11 — fan out to the kanban SSE feed.
                    if let Some(sse) = &sse {
                        let n = publish_sse(sse, &out, crate::time::now_unix_ns());
                        if n > 0 {
                            tracing::debug!(lines = n, "babel events published to SSE feed");
                        } else if !out.is_empty() {
                            // Feed-worthy events existed but nothing landed —
                            // usually just "no subscriber connected".
                            tracing::debug!("babel SSE publish: no subscribers");
                        }
                    }
                    for ev in &out {
                        match ev {
                            CronEvent::ThresholdBreached {
                                window_id,
                                score,
                                threshold,
                            } => {
                                tracing::warn!(
                                    window_id = %window_id,
                                    score,
                                    threshold,
                                    "babel: B_d crossed the operator threshold on the 15-min window"
                                );
                            }
                            CronEvent::WindowComputed(w) => {
                                tracing::debug!(
                                    window_secs = w.granularity.secs(),
                                    b_log = ?w.scores.b_log,
                                    b_bottleneck = w.scores.b_bottleneck,
                                    "babel window computed"
                                );
                            }
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "babel tick failed"),
            }
            // GOLD-DELTA-05 — 5-min norm refresh: 7-day p1/p99 per variable
            // per granularity, then reload the b_raw normaliser for the
            // primary (15-min) window into the scoring state.
            if now - last_norm_sweep >= NORM_SWEEP_SECS {
                last_norm_sweep = now;
                // GOLD-DELTA-07 — stamp collapse_30m on every window whose
                // 30-min horizon has fully ripened since the last sweep.
                let stamped = views
                    .with_writer(|conn| {
                        crate::analytics::babel::collapse::post_hoc_label_pass(conn, 1800, now)
                    })
                    .await;
                match stamped {
                    Ok(n) if n > 0 => {
                        tracing::debug!(windows = n, "babel post-hoc label pass stamped horizons");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "babel post-hoc label pass failed"),
                }
                // GOLD-DELTA-15 — self-calibrate the WORKING threshold from
                // the freshly stamped horizons. In-memory only; every
                // adjustment is logged with its Brier score. freedom.yaml's
                // babel.threshold stays the operator anchor.
                let current_threshold = state.threshold();
                let round = views
                    .with_writer(|conn| {
                        crate::analytics::babel::calibrate::calibrate_round(
                            conn,
                            current_threshold,
                            calibration_cursor_ts,
                        )
                    })
                    .await;
                match round {
                    Ok(Some(r)) => {
                        calibration_cursor_ts = r.cursor_ts;
                        if (r.new_threshold - current_threshold).abs() > f64::EPSILON {
                            tracing::info!(
                                evaluated = r.evaluated,
                                false_positives = r.false_positives,
                                false_negatives = r.false_negatives,
                                brier = r.brier,
                                old_threshold = current_threshold,
                                new_threshold = r.new_threshold,
                                "babel threshold self-calibrated (GOLD-DELTA-15; in-memory, anchor unchanged)"
                            );
                            state.set_threshold(r.new_threshold);
                        } else {
                            tracing::debug!(
                                evaluated = r.evaluated,
                                brier = r.brier,
                                "babel calibration round: predictions on target, threshold unchanged"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = %e, "babel calibration round failed"),
                }
                // GOLD-DELTA-06 — one-time epsilon calibration freeze:
                // `0.01 * median((D/A)*(H/V))` once MIN_SAMPLES 15-min
                // windows exist, persisted to freedom.yaml via the same
                // atomic secret-stripped writer `neoth hemispheres set`
                // uses. A failed persist keeps the in-memory value for this
                // run; the next boot recalibrates with the same rule.
                if cfg.epsilon_calibrated.is_none() {
                    let computed = views
                        .with_writer(|conn| {
                            crate::analytics::babel::norm::calibration_epsilon_from_db(
                                conn,
                                900,
                                crate::analytics::babel::norm::MIN_SAMPLES,
                            )
                        })
                        .await;
                    match computed {
                        Ok(Some(eps)) => {
                            state.set_epsilon(eps);
                            cfg.epsilon_calibrated = Some(eps);
                            tracing::info!(
                                epsilon = eps,
                                rule = "0.01_median_buffer_ratio_calibration",
                                "babel epsilon calibrated and frozen (GOLD-DELTA-06)"
                            );
                            let persist = tokio::task::spawn_blocking(move || {
                                let path = crate::config::FreedomConfig::default_path();
                                let mut fc = crate::config::FreedomConfig::load_from_path(&path)?;
                                if fc.babel.epsilon_calibrated.is_none() {
                                    fc.babel.epsilon_calibrated = Some(eps);
                                    fc.save_public_to_default_path()?;
                                }
                                anyhow::Ok(())
                            })
                            .await;
                            match persist {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => tracing::warn!(
                                    error = %e,
                                    "babel: epsilon persist to freedom.yaml failed (in-memory value active)"
                                ),
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "babel: epsilon persist task failed (in-memory value active)"
                                ),
                            }
                        }
                        Ok(None) => {} // not enough windows yet
                        Err(e) => {
                            tracing::warn!(error = %e, "babel: epsilon calibration query failed");
                        }
                    }
                }
                let eps = cfg.epsilon_calibrated;
                let refreshed = views
                    .with_writer(|conn| {
                        let mut primary_sweep_ok = true;
                        for g in crate::analytics::babel::window::WindowGranularity::all() {
                            if let Err(e) =
                                crate::analytics::babel::norm::sweep_norm(conn, g.secs(), now, eps)
                            {
                                if g.secs() == 900 {
                                    primary_sweep_ok = false;
                                }
                                tracing::warn!(
                                    error = %e,
                                    window_secs = g.secs(),
                                    "babel norm sweep failed"
                                );
                            }
                        }
                        if !primary_sweep_ok {
                            // Don't load a possibly-stale b_raw row over the
                            // known-valid in-memory normaliser.
                            return Ok(None);
                        }
                        crate::analytics::babel::norm::load_normaliser(conn, 900)
                    })
                    .await;
                match refreshed {
                    Ok(Some(n)) => {
                        tracing::debug!(
                            p1 = n.p1,
                            p99 = n.p99,
                            samples = n.sample_count,
                            "babel normaliser refreshed from b_raw sweep"
                        );
                        state.set_normaliser(n);
                    }
                    Ok(None) => {} // not calibrated yet — cold start persists
                    Err(e) => tracing::warn!(
                        error = %e,
                        "babel: normaliser reload failed; keeping previous calibration"
                    ),
                }
                // GOLD-DELTA-10 — federation: one-time consent prompt at
                // calibration maturity (panel Q3), then the pending-first
                // submit pipeline when the operator has opted in.
                let autonomy_u8 = autonomy_scalar(autonomy);
                let counts = views
                    .with_writer(crate::analytics::babel::store::submission_counts)
                    .await;
                match counts {
                    Ok(c) => {
                        let calibrated = cfg.epsilon_calibrated.is_some();
                        if !cfg.federate {
                            if !federation_prompted
                                && calibrated
                                && autonomy_u8 >= 3
                                && c.total_windows as usize
                                    >= crate::analytics::babel::federation::MIN_CALIBRATION_WINDOWS
                            {
                                federation_prompted = true;
                                let msg = "babel calibration complete — federation is now \
                                     possible. Contribute anonymized window records to the \
                                     shared research pool with `neoth babel federate --enable` \
                                     (sharing stays OFF until you do).";
                                tracing::info!("{msg}");
                                if let Some(sse) = &sse {
                                    let _ = sse.send(FeedEntry {
                                        ts_ns: crate::time::now_unix_ns(),
                                        event_type: 0x00,
                                        actor: "babel".to_string(),
                                        message: msg.to_string(),
                                    });
                                }
                            }
                        } else if let Some(key) = &federation_signing_key {
                            let gate = crate::analytics::babel::federation::ConsentGate {
                                federate_enabled: cfg.federate,
                                autonomy_level: autonomy_u8,
                                calibration_window_count: c.total_windows as usize,
                            };
                            let eps = cfg.epsilon_calibrated;
                            let queued = views
                                .with_writer(|conn| {
                                    crate::analytics::babel::federation::submit_pending_batch(
                                        conn,
                                        &gate,
                                        &federation_meta,
                                        key,
                                        &salt,
                                        &pending_dir,
                                        eps,
                                        now,
                                    )
                                })
                                .await;
                            match queued {
                                Ok(Some(o)) => tracing::info!(
                                    batch_id = %o.batch_id,
                                    windows = o.windows,
                                    "babel federation: batch queued"
                                ),
                                Ok(None) => {}
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "babel federation: submit pass failed"
                                ),
                            }
                            // Phase 2 — deliver pending batches when a live
                            // transport is available.
                            #[cfg(feature = "cluster-iroh")]
                            if let Some(endpoint) = &cfg.federation_endpoint {
                                let uploader = crate::analytics::babel::federation::IrohUploader {
                                    endpoint: endpoint.clone(),
                                };
                                match crate::analytics::babel::federation::drain_pending(
                                    &pending_dir,
                                    &uploader,
                                )
                                .await
                                {
                                    Ok((delivered, remaining)) if delivered + remaining > 0 => {
                                        tracing::info!(
                                            delivered,
                                            remaining,
                                            "babel federation: pending drain"
                                        );
                                    }
                                    Ok(_) => {}
                                    Err(e) => tracing::warn!(
                                        error = %e,
                                        "babel federation: pending drain failed"
                                    ),
                                }
                            }
                            #[cfg(not(feature = "cluster-iroh"))]
                            if cfg.federation_endpoint.is_some() {
                                tracing::debug!(
                                    "babel federation: endpoint configured but built without \
                                     cluster-iroh — batches stay pending for manual upload"
                                );
                            }
                            // GOLD-DELTA-14 — pooled predictor: pull (daily)
                            // + advisory. Strictly advisory by construction:
                            // apply_advisory is pure and nothing here touches
                            // set_threshold — DELTA-15 stays the only mutator.
                            let pubkey = cfg.federation_aggregator_pubkey.as_deref();
                            #[cfg(feature = "cluster-iroh")]
                            if let (Some(endpoint), Some(_)) = (&cfg.federation_endpoint, pubkey) {
                                if now - last_predictor_pull >= PREDICTOR_PULL_SECS {
                                    last_predictor_pull = now;
                                    let uploader =
                                        crate::analytics::babel::federation::IrohUploader {
                                            endpoint: endpoint.clone(),
                                        };
                                    match uploader.fetch_predictor().await {
                                        Ok(envelope) => {
                                            match crate::analytics::babel::federation::verify_pooled_predictor(
                                                &gate, &envelope, pubkey,
                                            ) {
                                                Ok(_) => {
                                                    if let Err(e) =
                                                        crate::analytics::babel::federation::cache_predictor(
                                                            pending_dir.parent().unwrap_or(&pending_dir),
                                                            &envelope,
                                                        )
                                                    {
                                                        tracing::warn!(error = %e,
                                                            "babel: predictor cache write failed");
                                                    }
                                                    predictor_advisory_logged = false;
                                                }
                                                Err(e) => tracing::warn!(error = %e,
                                                    "babel: pooled predictor REJECTED"),
                                            }
                                        }
                                        Err(e) => tracing::debug!(error = %e,
                                            "babel: predictor pull failed (will retry tomorrow)"),
                                    }
                                }
                            }
                            if !predictor_advisory_logged {
                                predictor_advisory_logged = true;
                                let cache_dir = pending_dir
                                    .parent()
                                    .map(std::path::Path::to_path_buf)
                                    .unwrap_or_else(|| pending_dir.clone());
                                match crate::analytics::babel::federation::load_cached_predictor(
                                    &cache_dir, &gate, pubkey,
                                ) {
                                    Ok(Some(p)) => {
                                        let advisory =
                                            crate::analytics::babel::federation::apply_advisory(
                                                &p,
                                                state.threshold(),
                                            );
                                        let msg = format!(
                                            "babel pooled predictor (ADVISORY, never auto-applied): \
                                             pool threshold {:.3} vs local {:.3} (delta {:+.3}), \
                                             trained on {} instances, OOS Brier {:.3}",
                                            advisory.pool_threshold,
                                            advisory.local_threshold,
                                            advisory.delta,
                                            advisory.trained_on_instances,
                                            advisory.brier_oos,
                                        );
                                        tracing::info!("{msg}");
                                        if let Some(sse) = &sse {
                                            let _ = sse.send(FeedEntry {
                                                ts_ns: crate::time::now_unix_ns(),
                                                event_type: 0x00,
                                                actor: "babel".to_string(),
                                                message: msg,
                                            });
                                        }
                                    }
                                    Ok(None) => {} // no pool data yet
                                    Err(e) => tracing::warn!(error = %e,
                                        "babel: cached predictor failed re-verification"),
                                }
                            }
                        } else {
                            tracing::warn!(
                                "babel federation: enabled but signing key unavailable — \
                                 batches cannot be signed, nothing submitted"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "babel federation: submission counts failed");
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::SegmentHeaderV2;

    fn frame_bytes(event_type: u8, payload: &[u8]) -> Vec<u8> {
        let h = HeaderBuilder::new(event_type, payload).build();
        encode_frame(&h, payload)
    }

    fn segment(frames: &[u8]) -> Vec<u8> {
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], 0);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(frames);
        seg
    }

    fn mcp_payload(tool: &str, hash: &str, ts: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "server_id": "srv", "tool": tool, "arguments_hash": hash,
            "content_bytes": 10, "is_error": false, "ts_unix": ts,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let cfg = BabelConfig {
            enabled: false,
            ..BabelConfig::default()
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let views = ViewsExecutor::open(&dir.path().join("views.db"), 1).expect("views");
        let h = spawn_babel_cron_loop(
            cfg,
            AutonomyLevel::Standard,
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            views,
            None,
            None,
        );
        assert!(h.is_none(), "disabled observer must not spawn a task");
    }

    #[test]
    fn autonomy_scalar_matches_feature_doc() {
        assert_eq!(autonomy_scalar(AutonomyLevel::Strict), 1);
        assert_eq!(autonomy_scalar(AutonomyLevel::Standard), 2);
        assert_eq!(autonomy_scalar(AutonomyLevel::Elevated), 3);
        assert_eq!(autonomy_scalar(AutonomyLevel::Full), 4);
        assert_eq!(autonomy_scalar(AutonomyLevel::Custom), 2);
    }

    #[test]
    fn federation_model_family_uses_resolved_primary_provider_config() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::AnthropicApi);
        config.provider_model = Some("@primary".to_string());
        config.models_aliases.insert(
            "@primary".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
        );

        assert_eq!(
            configured_primary_model_family(Some(&config)),
            "anthropic_api/claude-3"
        );
        assert_eq!(configured_primary_model_family(None), "unknown");
    }

    #[test]
    fn repeated_identical_mcp_call_synthesises_retry() {
        let mut m = MapperState::default();
        let first = map_frame(
            EVENT_TYPE_MCP_TOOL_CALLED,
            0,
            &mcp_payload("bash", "abc", 100),
            &mut m,
        );
        assert_eq!(first.len(), 1, "first call: tool-called only");
        let second = map_frame(
            EVENT_TYPE_MCP_TOOL_CALLED,
            0,
            &mcp_payload("bash", "abc", 150),
            &mut m,
        );
        assert!(
            second
                .iter()
                .any(|e| matches!(e.kind, WalEventKind::Retry { .. })),
            "identical (tool, arguments_hash) within horizon → Retry"
        );
        let much_later = map_frame(
            EVENT_TYPE_MCP_TOOL_CALLED,
            0,
            &mcp_payload("bash", "abc", 400),
            &mut m,
        );
        assert!(
            !much_later
                .iter()
                .any(|e| matches!(e.kind, WalEventKind::Retry { .. })),
            "repeat beyond the horizon is not a retry"
        );
    }

    #[test]
    fn provider_response_after_fallback_synthesises_success() {
        let mut m = MapperState::default();
        let fb = serde_json::to_vec(&serde_json::json!({
            "to_provider": "openai", "reason": "quota_429", "hop": 1, "ts_unix": 100,
        }))
        .unwrap();
        let attempt = map_frame(EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED, 0, &fb, &mut m);
        assert!(
            attempt
                .iter()
                .any(|e| matches!(e.kind, WalEventKind::FallbackAttempt { .. }))
        );
        let resp = serde_json::to_vec(&serde_json::json!({
            "output_tokens": 42, "ts_unix": 130,
        }))
        .unwrap();
        let out = map_frame(EVENT_TYPE_PROVIDER_RESPONSE, 0, &resp, &mut m);
        assert!(
            out.iter()
                .any(|e| matches!(&e.kind, WalEventKind::FallbackResult { success: true, .. })),
            "response within horizon completes the pending fallback"
        );
        assert!(m.pending_fallback.is_none(), "pending slot consumed");
    }

    #[test]
    fn scan_cursor_only_emits_new_frames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seg_path = dir.path().join("000001.wal");
        let f1 = frame_bytes(
            EVENT_TYPE_AGENT_DISPATCHED,
            &serde_json::to_vec(&serde_json::json!({"agent_name": "a1", "ts_unix": 10})).unwrap(),
        );
        std::fs::write(&seg_path, segment(&f1)).expect("write seg");

        let mut scan = ScanState::default();
        // Fast-forward pass: records offsets, emits nothing.
        let init = scan.scan(dir.path(), false);
        assert!(init.is_empty());
        // No new frames → no events.
        assert!(scan.scan(dir.path(), true).is_empty());
        // Append a second frame → exactly that one is emitted.
        let f2 = frame_bytes(
            EVENT_TYPE_AGENT_DISPATCHED,
            &serde_json::to_vec(&serde_json::json!({"agent_name": "a2", "ts_unix": 20})).unwrap(),
        );
        let mut all = segment(&f1);
        all.extend_from_slice(&f2);
        std::fs::write(&seg_path, all).expect("rewrite seg");
        let events = scan.scan(dir.path(), true);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].kind,
            WalEventKind::AgentDispatched { agent_id } if agent_id == "a2"
        ));
    }

    #[test]
    fn publish_sse_pushes_fifteen_min_windows_and_breaches_only() {
        use crate::analytics::babel::collapse::CollapseDetection;
        use crate::analytics::babel::feature::{
            BabelFeatures, FeatureAlgorithmVersions, KdPosture,
        };
        use crate::analytics::babel::score::BabelScores;
        use crate::analytics::babel::window::BabelWindow;

        let mk_window = |granularity: WindowGranularity| {
            Box::new(BabelWindow {
                id: "w-test".into(),
                session_id_pseudo: "a1b2c3d4e5f60718".into(),
                granularity,
                ts_start: 0,
                ts_end: granularity.secs() as i64,
                features: BabelFeatures {
                    c: 0.5,
                    k: 0.5,
                    m: 0.5,
                    a: 0.5,
                    v: 0.5,
                    d: 1.0,
                    h: 1.0,
                    k_d_posture: KdPosture::default(),
                    algorithm_versions: FeatureAlgorithmVersions::default(),
                },
                scores: BabelScores {
                    b_log: Some(-1.0),
                    b_mult: None,
                    b_mult_epsilon: None,
                    b_mult_epsilon_rule: "0.01_median_buffer_ratio_calibration".into(),
                    b_bottleneck: 0.5,
                },
                collapse: CollapseDetection::default(),
                signal_posture: crate::analytics::babel::signals::SignalPosture::default(),
                schema_version: BabelWindow::SCHEMA_VERSION.into(),
                algorithm_version_c: "C_d_v0".into(),
                algorithm_version_k: "K_d_v0".into(),
                algorithm_version_m: "M_d_v0".into(),
                algorithm_version_a: "A_d_v0".into(),
                algorithm_version_v: "V_d_v0".into(),
                algorithm_version_d: "D_d_v0".into(),
                algorithm_version_h: "H_d_v0".into(),
            })
        };
        let (tx, mut rx) = tokio::sync::broadcast::channel::<FeedEntry>(8);
        let events = vec![
            CronEvent::WindowComputed(mk_window(WindowGranularity::FiveMin)),
            CronEvent::WindowComputed(mk_window(WindowGranularity::FifteenMin)),
            CronEvent::ThresholdBreached {
                window_id: "w-test".into(),
                score: 0.91,
                threshold: 0.8,
            },
        ];
        let published = publish_sse(&tx, &events, 42);
        assert_eq!(published, 2, "5-min window stays off the feed");
        let first = rx.try_recv().expect("15-min line");
        assert_eq!(first.actor, "babel");
        assert!(
            first.message.contains("900s"),
            "carries window_secs: {}",
            first.message
        );
        let second = rx.try_recv().expect("breach line");
        assert!(second.message.contains("THRESHOLD BREACH"));
        assert!(rx.try_recv().is_err(), "nothing else published");
    }

    #[test]
    fn shrunken_segment_resets_cursor_instead_of_stalling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seg_path = dir.path().join("000001.wal");
        let f1 = frame_bytes(
            EVENT_TYPE_AGENT_DISPATCHED,
            &serde_json::to_vec(&serde_json::json!({"agent_name": "a1", "ts_unix": 10})).unwrap(),
        );
        let f2 = frame_bytes(
            EVENT_TYPE_AGENT_DISPATCHED,
            &serde_json::to_vec(&serde_json::json!({"agent_name": "a2", "ts_unix": 20})).unwrap(),
        );
        let mut both = segment(&f1);
        both.extend_from_slice(&f2);
        std::fs::write(&seg_path, &both).expect("write seg");

        let mut scan = ScanState::default();
        scan.scan(dir.path(), false); // cursor at end of the 2-frame segment
        // Rewrite SHORTER (compaction/truncation) → cursor must reset, not stall.
        std::fs::write(&seg_path, segment(&f1)).expect("rewrite shorter");
        let events = scan.scan(dir.path(), true);
        assert_eq!(events.len(), 1, "reset re-emits the surviving frame");
        assert!(matches!(
            &events[0].kind,
            WalEventKind::AgentDispatched { agent_id } if agent_id == "a1"
        ));
    }
}
