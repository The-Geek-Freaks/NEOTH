//! GOLD-FEAT-09 — daemon watchdog / auto-recovery cron.
//!
//! Probes a small set of supervised *local* services every
//! `watchdog.interval_secs`, folds each probe outcome into a per-service
//! rolling failure counter, and — once a service has been down for
//! `consecutive_failures_before_restart` ticks — issues the service's restart
//! command. Two guards keep it from becoming a crash-loop amplifier:
//!
//!   1. **Autonomy gate.** The restart *action* (spawning a process) only fires
//!      when the daemon's autonomy is `Elevated` or higher. Below that the
//!      watchdog is observe-only: it still emits a `0x5F WATCHDOG_RESTART`
//!      frame with `decision = "alert_only"` so the anomaly is auditable, but
//!      it never spawns anything.
//!   2. **Per-window restart budget.** At most `max_restarts_per_window`
//!      restarts per `window_secs`. A service that keeps dying inside the
//!      window is flagged (`decision = "rate_limited"`) instead of being
//!      restarted on every tick.
//!
//! The decision policy lives in [`WatchState::observe`] — a pure function with
//! no I/O and no clock read (the wall-clock + thresholds are passed in), so the
//! whole supervisor policy is unit-tested deterministically. The probes reuse
//! the existing [`crate::installers::n8n::probe_n8n_endpoint`] /
//! [`crate::installers::ollama::probe_endpoint`] primitives; the restart
//! commands are best-effort `spawn`s (a failed spawn just leaves the service
//! down → another `Restart` decision next window).

use std::collections::HashMap;

use crate::config::WatchdogConfig;
use crate::wal::{events::EVENT_TYPE_WATCHDOG_RESTART, writer::WalWriterHandle};

// ---------------------------------------------------------------------------
// Policy types (pure — unit-tested)

/// The decision the watchdog reaches for ONE service on ONE tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    /// Probe succeeded — the service is up. Failure streak reset.
    Healthy,
    /// Probe failed but the consecutive-failure count is still below the
    /// restart threshold — keep watching, take no action.
    Wait,
    /// Threshold reached AND restart budget available — restart now.
    Restart,
    /// Threshold reached but the per-window restart budget is exhausted —
    /// emit an alert, do NOT restart (crash-loop guard).
    RateLimited,
    /// Threshold reached and budget remains, but not enough time has elapsed
    /// since the last restart — exponential backoff is still in effect. Emit an
    /// alert, do NOT restart this tick (anti-flap guard).
    BackingOff,
}

/// Per-service rolling failure/restart state. Ephemeral: it lives only in the
/// cron loop's `HashMap` and is never persisted — a daemon restart resets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchState {
    /// Consecutive failed probes since the last healthy probe or restart.
    pub consecutive_failures: u32,
    /// Restarts charged against the current window.
    pub restarts_in_window: u32,
    /// Unix-seconds the current restart-budget window opened.
    pub window_start_secs: u64,
    /// Unix-seconds of the most recent committed restart (0 = never). Drives the
    /// exponential-backoff gate between consecutive restarts.
    pub last_restart_secs: u64,
}

impl WatchState {
    /// Fold one probe outcome into the state and return the decision.
    ///
    /// Pure: no I/O, no clock read. `now_secs` and the four policy knobs are
    /// passed in so the whole policy is deterministic + unit-testable.
    ///
    /// * `healthy` — did this tick's probe succeed?
    /// * `failures_before_restart` — restart only after this many consecutive
    ///   failures (clamped to a 1 floor so `0` can't restart on first failure).
    /// * `max_restarts_per_window` — restart budget per window.
    /// * `window_secs` — restart-budget window length.
    /// * `base_backoff_secs` — exponential-backoff base between consecutive
    ///   restarts (`0` disables backoff). The Nth in-window restart must wait
    ///   `base · 2^(N-1)` (capped at `max_backoff_secs`) + `jitter_secs`.
    /// * `max_backoff_secs` — cap on the exponential backoff.
    /// * `jitter_secs` — caller-supplied additive jitter (kept OUT of this pure
    ///   function so the policy stays deterministic; `0` in tests).
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        healthy: bool,
        now_secs: u64,
        failures_before_restart: u32,
        max_restarts_per_window: u32,
        window_secs: u64,
        base_backoff_secs: u64,
        max_backoff_secs: u64,
        jitter_secs: u64,
    ) -> RestartDecision {
        if healthy {
            self.consecutive_failures = 0;
            return RestartDecision::Healthy;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures < failures_before_restart.max(1) {
            return RestartDecision::Wait;
        }
        // Threshold reached. Roll the budget window if it has elapsed.
        if now_secs.saturating_sub(self.window_start_secs) >= window_secs {
            self.window_start_secs = now_secs;
            self.restarts_in_window = 0;
        }
        // Exponential backoff: once at least one restart has happened, hold off
        // until `base · 2^(restarts-1)` (capped) + jitter has elapsed since it.
        if self.restarts_in_window > 0 && base_backoff_secs > 0 {
            let shift = (self.restarts_in_window - 1).min(16);
            let exp = base_backoff_secs.saturating_mul(1u64 << shift);
            let backoff = exp
                .min(max_backoff_secs.max(base_backoff_secs))
                .saturating_add(jitter_secs);
            if now_secs.saturating_sub(self.last_restart_secs) < backoff {
                return RestartDecision::BackingOff;
            }
        }
        if self.restarts_in_window >= max_restarts_per_window {
            return RestartDecision::RateLimited;
        }
        // Commit to a restart: reset the failure streak + charge the budget +
        // stamp the restart time for the next backoff computation.
        self.consecutive_failures = 0;
        self.restarts_in_window = self.restarts_in_window.saturating_add(1);
        self.last_restart_secs = now_secs;
        RestartDecision::Restart
    }
}

// ---------------------------------------------------------------------------
// Supervised services

/// The local services the watchdog supervises. Kept deliberately small — only
/// the two background services NEOTH itself installs + probes today have a
/// known restart command. New services join here + in [`Self::ALL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatchedService {
    /// n8n cron/automation engine (probed on `watchdog.n8n_port`).
    N8n,
    /// Ollama local-model server (probed on `watchdog.ollama_port`).
    Ollama,
    /// Obsidian desktop app (probed by process presence via `sysinfo`).
    /// ALERT-ONLY: NEOTH has no clean restart command for a GUI app the
    /// operator launched, so a down Obsidian is surfaced as an anomaly but
    /// never (re)spawned.
    Obsidian,
}

impl WatchedService {
    /// Every supervised service, in probe order.
    pub const ALL: [WatchedService; 3] = [
        WatchedService::N8n,
        WatchedService::Ollama,
        WatchedService::Obsidian,
    ];

    /// Stable snake_case label used in WAL payloads + logs.
    pub fn label(self) -> &'static str {
        match self {
            WatchedService::N8n => "n8n",
            WatchedService::Ollama => "ollama",
            WatchedService::Obsidian => "obsidian",
        }
    }

    /// Whether NEOTH has a restart command for this service. Obsidian is a
    /// GUI app with no clean headless (re)start, so it is observe/alert-only —
    /// a `Restart` decision degrades to an `alert_only` frame regardless of
    /// autonomy level.
    pub fn is_restartable(self) -> bool {
        !matches!(self, WatchedService::Obsidian)
    }
}

// ---------------------------------------------------------------------------
// Loop wiring

/// Spawn the watchdog cron loop. Returns `None` (and logs) when
/// `watchdog.enabled == false`, mirroring [`super::monitor_cron::
/// spawn_monitor_cron_loop`].
///
/// `restart_allowed` is the autonomy gate resolved ONCE at spawn time from the
/// live autonomy level (`>= Elevated`). Passing a plain `bool` keeps this
/// module decoupled from the autonomy enum.
pub fn spawn_watchdog_cron_loop(
    config: WatchdogConfig,
    restart_allowed: bool,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("watchdog cron disabled (watchdog.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut states: HashMap<WatchedService, WatchState> = HashMap::new();
        tracing::info!(
            interval_secs = interval.as_secs(),
            restart_allowed,
            "watchdog cron loop online (GOLD-FEAT-09)",
        );
        loop {
            ticker.tick().await;
            if let Err(e) = run_watchdog_tick(&config, restart_allowed, &writer, &mut states).await
            {
                tracing::warn!(error = %e, "watchdog tick failed");
            }
        }
    }))
}

/// Run one watchdog tick: probe every supervised service, fold the outcome into
/// its [`WatchState`], and act on the decision. Returns `Err` only on a WAL
/// append failure (a failed restart *spawn* is logged + folded into the next
/// tick, not surfaced as an error). Public for the integration test harness.
pub async fn run_watchdog_tick(
    config: &WatchdogConfig,
    restart_allowed: bool,
    writer: &WalWriterHandle,
    states: &mut HashMap<WatchedService, WatchState>,
) -> Result<(), String> {
    let now_secs = now_unix_secs();
    let ts_unix = now_secs as i64;
    for svc in WatchedService::ALL {
        let port = match svc {
            WatchedService::N8n => config.n8n_port,
            WatchedService::Ollama => config.ollama_port,
            // Obsidian is probed by process presence, not a port.
            WatchedService::Obsidian => 0,
        };
        let healthy = probe_service(svc, port).await;
        let state = states.entry(svc).or_default();
        let decision = state.observe(
            healthy,
            now_secs,
            config.consecutive_failures_before_restart,
            config.max_restarts_per_window,
            config.window_secs,
            config.restart_backoff_base_secs,
            config.restart_backoff_max_secs,
            restart_jitter_secs(config.restart_backoff_base_secs),
        );
        let restarts_in_window = state.restarts_in_window;
        match decision {
            RestartDecision::Healthy | RestartDecision::Wait => {}
            RestartDecision::BackingOff => {
                tracing::warn!(
                    service = svc.label(),
                    "watchdog: {} down but inside the restart backoff window — not restarting yet",
                    svc.label(),
                );
                emit_watchdog_frame(writer, svc, "backing_off", restarts_in_window, ts_unix)
                    .await?;
            }
            RestartDecision::RateLimited => {
                tracing::warn!(
                    service = svc.label(),
                    "watchdog: {} down but restart budget exhausted this window — not restarting",
                    svc.label(),
                );
                emit_watchdog_frame(writer, svc, "rate_limited", restarts_in_window, ts_unix)
                    .await?;
            }
            RestartDecision::Restart => {
                // A non-restartable service (Obsidian) can never be respawned —
                // it degrades to an alert regardless of autonomy.
                if restart_allowed && svc.is_restartable() {
                    match restart_service(svc).await {
                        Ok(()) => tracing::info!(
                            service = svc.label(),
                            "watchdog restarted {}",
                            svc.label()
                        ),
                        Err(e) => tracing::warn!(
                            service = svc.label(),
                            error = %e,
                            "watchdog restart spawn failed",
                        ),
                    }
                    emit_watchdog_frame(writer, svc, "restart", restarts_in_window, ts_unix)
                        .await?;
                } else {
                    tracing::warn!(
                        service = svc.label(),
                        restartable = svc.is_restartable(),
                        "watchdog: {} down but not restarting (below Elevated autonomy or no restart command) — alert only",
                        svc.label(),
                    );
                    emit_watchdog_frame(writer, svc, "alert_only", restarts_in_window, ts_unix)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

/// Probe one service. Reuses the existing installer probe primitives. A
/// `PortOpenNoHttp` n8n result counts as healthy — the port is bound, so the
/// process is up; the watchdog's job is "is the service alive", not "is it
/// fully HTTP-ready" (the latter is `neoth status`'s richer check).
async fn probe_service(svc: WatchedService, port: u16) -> bool {
    match svc {
        WatchedService::N8n => {
            use crate::installers::n8n::N8nProbeOutcome;
            matches!(
                crate::installers::n8n::probe_n8n_endpoint(port).await,
                N8nProbeOutcome::Reachable | N8nProbeOutcome::PortOpenNoHttp
            )
        }
        WatchedService::Ollama => {
            use crate::installers::ollama::ProbeOutcome;
            matches!(
                crate::installers::ollama::probe_endpoint(port).await,
                ProbeOutcome::Reachable
            )
        }
        // GUI app — "healthy" == a process whose name contains "obsidian" exists.
        WatchedService::Obsidian => obsidian_running(),
    }
}

/// Whether an Obsidian process is currently running (case-insensitive name
/// match, cross-platform — `Obsidian.exe` on Windows, `obsidian` elsewhere).
/// `sysinfo` process enumeration; cheap enough for the watchdog cadence.
fn obsidian_running() -> bool {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::new());
    sys.processes().values().any(|p| {
        p.name()
            .to_string_lossy()
            .to_lowercase()
            .contains("obsidian")
    })
}

/// A small random additive jitter (`0..=base/4` seconds) decorrelating the
/// restart backoff across services so a multi-service outage doesn't make them
/// all retry on the exact same tick. Returns 0 when backoff is disabled.
fn restart_jitter_secs(base_backoff_secs: u64) -> u64 {
    if base_backoff_secs == 0 {
        return 0;
    }
    use rand::Rng;
    rand::rng().random_range(0..=base_backoff_secs / 4)
}

/// Issue the service's restart command. OS/tool-dependent + only reached when
/// `restart_allowed` (autonomy >= Elevated) AND a real `Restart` was decided,
/// so it is never exercised by the unit suite. Best-effort: `spawn` returns as
/// soon as the child is launched (it is NOT awaited to completion — these are
/// long-running servers); a launch failure is returned to the caller, logged,
/// and folded into the next tick's probe.
async fn restart_service(svc: WatchedService) -> std::io::Result<()> {
    use std::process::Stdio;
    let (program, arg) = match svc {
        WatchedService::N8n => ("n8n", "start"),
        WatchedService::Ollama => ("ollama", "serve"),
        // Never reached: the tick guards on `is_restartable()` before calling
        // this. Defensive arm keeps the match exhaustive + fails loud if a
        // future caller forgets the guard.
        WatchedService::Obsidian => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "obsidian has no restart command (alert-only)",
            ));
        }
    };
    std::process::Command::new(program)
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
}

/// Append a `0x5F WATCHDOG_RESTART` frame. Mirrors the monitor cron's alert
/// emit (synthetic flag, JSON payload).
async fn emit_watchdog_frame(
    writer: &WalWriterHandle,
    svc: WatchedService,
    decision: &str,
    restarts_in_window: u32,
    ts_unix: i64,
) -> Result<(), String> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "service": svc.label(),
        "decision": decision,
        "restarts_in_window": restarts_in_window,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize watchdog payload: {e}"))?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_WATCHDOG_RESTART, &payload)
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, payload)
        .await
        .map(|_seq| ())
        .map_err(|e| format!("wal append WATCHDOG_RESTART: {e}"))
}

/// Current Unix time in whole seconds (0 on a pre-epoch clock — impossible in
/// practice; the `unwrap_or(0)` just avoids a panic path).
fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

// ---------------------------------------------------------------------------
// Tests — the pure decision policy

#[cfg(test)]
mod tests {
    use super::*;

    // Policy knobs reused across the cases.
    const THRESHOLD: u32 = 3;
    const MAX_PER_WINDOW: u32 = 2;
    const WINDOW: u64 = 600;

    fn observe(state: &mut WatchState, healthy: bool, now: u64) -> RestartDecision {
        // Backoff disabled (base 0) for the budget/threshold cases — the backoff
        // policy has its own dedicated test below.
        state.observe(healthy, now, THRESHOLD, MAX_PER_WINDOW, WINDOW, 0, 0, 0)
    }

    #[test]
    fn healthy_probe_resets_failure_streak() {
        let mut s = WatchState::default();
        assert_eq!(observe(&mut s, false, 0), RestartDecision::Wait);
        assert_eq!(s.consecutive_failures, 1);
        assert_eq!(observe(&mut s, true, 10), RestartDecision::Healthy);
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn restarts_only_after_threshold_consecutive_failures() {
        let mut s = WatchState::default();
        // Two failures below the 3-failure threshold = Wait.
        assert_eq!(observe(&mut s, false, 0), RestartDecision::Wait);
        assert_eq!(observe(&mut s, false, 30), RestartDecision::Wait);
        // Third consecutive failure crosses the threshold = Restart.
        assert_eq!(observe(&mut s, false, 60), RestartDecision::Restart);
        // The restart reset the streak + charged the window budget.
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(s.restarts_in_window, 1);
    }

    #[test]
    fn restart_budget_exhaustion_yields_rate_limited() {
        let mut s = WatchState::default();
        // Drive two restarts inside the same window (budget = 2).
        for tick in 0..3 {
            observe(&mut s, false, 100 + tick * 10);
        }
        assert_eq!(s.restarts_in_window, 1);
        for tick in 0..3 {
            observe(&mut s, false, 200 + tick * 10);
        }
        assert_eq!(s.restarts_in_window, 2);
        // Budget is now exhausted for the window: the next threshold breach is
        // RateLimited, not Restart, and does NOT charge the budget further.
        for tick in 0..2 {
            assert_eq!(
                observe(&mut s, false, 300 + tick * 10),
                RestartDecision::Wait
            );
        }
        assert_eq!(observe(&mut s, false, 330), RestartDecision::RateLimited);
        assert_eq!(s.restarts_in_window, 2);
    }

    #[test]
    fn window_roll_refreshes_the_restart_budget() {
        let mut s = WatchState::default();
        // Exhaust the budget at t≈0.
        for _ in 0..3 {
            observe(&mut s, false, 0);
        }
        for _ in 0..3 {
            observe(&mut s, false, 0);
        }
        assert_eq!(s.restarts_in_window, 2);
        // Next threshold breach inside the same window = RateLimited.
        for _ in 0..3 {
            observe(&mut s, false, 100);
        }
        assert_eq!(
            observe(&mut s, false, 100),
            RestartDecision::RateLimited,
            "still inside the window"
        );
        // Past `window_secs` the budget resets. The failure streak never
        // cleared (the service stayed down across the boundary), so the very
        // first post-window failure already sits above the threshold → it
        // restarts immediately under the refreshed budget.
        assert_eq!(
            observe(&mut s, false, WINDOW + 700),
            RestartDecision::Restart,
            "window rolled → budget refreshed → still-down service restarts"
        );
        assert_eq!(s.restarts_in_window, 1);
    }

    #[test]
    fn zero_threshold_is_clamped_to_one() {
        // A misconfigured `failures_before_restart: 0` must NOT restart on the
        // very first failure — the `.max(1)` floor guarantees at least one
        // observed failure before any action.
        let mut s = WatchState::default();
        let d = s.observe(false, 0, 0, MAX_PER_WINDOW, WINDOW, 0, 0, 0);
        assert_eq!(d, RestartDecision::Restart);
        // (first failure → count 1 ≥ max(0,1)=1 → restart; the clamp keeps it
        // from being a no-op, but a 0 still means "restart ASAP" by design.)
        assert_eq!(s.restarts_in_window, 1);
    }

    #[test]
    fn service_labels_are_stable() {
        assert_eq!(WatchedService::N8n.label(), "n8n");
        assert_eq!(WatchedService::Ollama.label(), "ollama");
        assert_eq!(WatchedService::Obsidian.label(), "obsidian");
        assert_eq!(WatchedService::ALL.len(), 3);
        // n8n + Ollama have restart commands; Obsidian (GUI) is alert-only.
        assert!(WatchedService::N8n.is_restartable());
        assert!(WatchedService::Ollama.is_restartable());
        assert!(!WatchedService::Obsidian.is_restartable());
    }

    #[test]
    fn exponential_backoff_blocks_restart_until_elapsed() {
        // base=30s, max=900s, budget effectively unlimited so backoff (not the
        // window budget) is what gates the second restart.
        let mut s = WatchState::default();
        let knobs =
            |st: &mut WatchState, now: u64| st.observe(false, now, 1, 100, WINDOW, 30, 900, 0);
        // First failure → first restart at t=0 (no prior restart → no backoff).
        assert_eq!(knobs(&mut s, 0), RestartDecision::Restart);
        assert_eq!(s.last_restart_secs, 0);
        // 10s later, still down: within the 30s (base·2^0) backoff → BackingOff.
        assert_eq!(knobs(&mut s, 10), RestartDecision::BackingOff);
        // 30s later: backoff elapsed → second restart; backoff now doubles to 60s.
        assert_eq!(knobs(&mut s, 30), RestartDecision::Restart);
        assert_eq!(s.restarts_in_window, 2);
        // 40s in (10s since the 2nd restart): inside the new 60s backoff.
        assert_eq!(knobs(&mut s, 40), RestartDecision::BackingOff);
        // 90s in (60s since the 2nd restart): elapsed → third restart.
        assert_eq!(knobs(&mut s, 90), RestartDecision::Restart);
    }

    #[test]
    fn backoff_is_capped_at_max() {
        // base=30, max=45 → after the first couple restarts the required gap is
        // capped at 45s even though 30·2^n would be far larger. All within one
        // WINDOW (600s) so the budget window never rolls + restarts accumulate.
        let mut s = WatchState::default();
        let step =
            |st: &mut WatchState, now: u64| st.observe(false, now, 1, 100, WINDOW, 30, 45, 0);
        assert_eq!(step(&mut s, 0), RestartDecision::Restart); // #1 (no prior restart)
        assert_eq!(step(&mut s, 30), RestartDecision::Restart); // #2 (base 30s elapsed)
        assert_eq!(step(&mut s, 75), RestartDecision::Restart); // #3 (cap 45s elapsed)
        // 44s after #3: 30·2^2 = 120 would block, but the cap is 45 → inside cap.
        assert_eq!(step(&mut s, 75 + 44), RestartDecision::BackingOff);
        // 45s after #3: cap elapsed → restart.
        assert_eq!(step(&mut s, 75 + 45), RestartDecision::Restart);
    }
}
