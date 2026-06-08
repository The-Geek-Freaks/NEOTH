//! B-6 Item 4d — stuck-cleaner PID hunt for runaway `claude` processes.
//!
//! Existing `providers/tmux_sweeper.rs` reaps idle TMUX SESSIONS by
//! activity timestamp. This module reaps the harder failure mode:
//! a `claude` (or `claude-cli`) PROCESS that has been running > N
//! minutes at near-zero CPU (mid tool-call deadlock, hung
//! authentication waiting on a closed browser, stuck on a stale
//! WebSocket). The tmux session looks live (low idle_secs) but the
//! pane is unresponsive — only PID-CPU monitoring catches it.
//!
//! Port of bridge.py's `stuck_cleaner`:
//!   1. Walk /proc (or sysinfo's portable surface) looking for
//!      processes whose name matches `claude` / `claude-cli`.
//!   2. For each, compute runtime + recent CPU usage.
//!   3. Mark "stuck" any process with runtime > stuck_threshold
//!      AND avg recent CPU < idle_cpu_threshold.
//!   4. Operator-side: surface for `neoth doctor` first (shipped as a
//!      WARN check, GOLD-WIRE-05), then kill-after-confirm MANUALLY
//!      (`kill` / `taskkill`). Auto-kill lands later behind an explicit
//!      `freedom.yaml::claude_cli.stuck_cleaner.auto_kill: true` opt-in
//!      (off by default per the AGENTER hard rule "no destructive
//!      auto-action without operator GO per command").
//!
//! Scope (this commit):
//!   - Pure-fn `classify_process(meta, threshold)` so the policy is
//!     testable without spawning anything.
//!   - `scan_stuck_processes(thresholds)` async wrapper that uses
//!     `sysinfo::System` to enumerate + classify; returns a vec of
//!     `StuckProcess` descriptors for operator-facing surfaces.
//!   - Defaults pinned to bridge.py: stuck_threshold=15min,
//!     idle_cpu=1% — drift-guarded so an upstream bridge tune
//!     surfaces in test output.
//!
//! Wiring: the `neoth doctor` WARN check shipped in GOLD-WIRE-05
//! (`cli/doctor.rs::check_stuck_claude_processes`). Still deferred: a
//! dedicated `neoth doctor stuck-clean` review/kill subcommand + the
//! auto-kill opt-in — those land when the operator UX is locked in.

use std::time::Duration;

use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// One operator-tunable thresholds bundle. Defaults match
/// bridge.py + the Konsens B-6 design notes; operators raise
/// `idle_cpu_pct` for hosts running NEOTH alongside other low-CPU
/// long-running processes that should not get classified as stuck.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StuckThresholds {
    /// Process runtime above which we even consider it for the
    /// stuck check. Below this, "newly spawned + waiting for first
    /// network response" cases look like 0% CPU but are fine.
    pub min_runtime: Duration,
    /// CPU% below which a process is considered "doing nothing".
    /// Stored as f32 in 0.0..=100.0; bridge.py uses 1.0.
    pub idle_cpu_pct: f32,
}

impl Default for StuckThresholds {
    fn default() -> Self {
        Self {
            min_runtime: Duration::from_secs(15 * 60),
            idle_cpu_pct: 1.0,
        }
    }
}

/// Snapshot of one process as seen by the hunter. Pure data — no
/// reference into a live `System`, so the operator surface can defer
/// rendering without lifetime gymnastics.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessMeta {
    pub pid: u32,
    pub name: String,
    pub runtime: Duration,
    pub cpu_pct: f32,
}

/// Operator-facing summary of one process the hunter flagged as
/// stuck. Carries the inputs that drove the classification so
/// `neoth doctor` can show "why it's stuck" without re-running the
/// scan.
#[derive(Clone, Debug, PartialEq)]
pub struct StuckProcess {
    pub meta: ProcessMeta,
    pub thresholds: StuckThresholds,
    pub hint: &'static str,
}

/// Process-name strings the hunter recognises as `claude`. Pinned
/// so the test below catches a future binary-rename upstream that
/// would silently let stuck processes slip through.
pub const CLAUDE_PROCESS_NAMES: &[&str] = &["claude", "claude-cli"];

/// True ⇔ `name` matches one of the recognised `claude` binary
/// names. Case-insensitive on Windows (where exe names sometimes
/// arrive title-cased) and exact-match on Linux/macOS.
pub fn is_claude_process_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stripped = lower.strip_suffix(".exe").unwrap_or(&lower);
    CLAUDE_PROCESS_NAMES.contains(&stripped)
}

/// Pure-fn classifier: True ⇔ the process meets BOTH the runtime
/// floor AND the CPU ceiling. Below the runtime floor every
/// process looks idle; the AND gate is what stops the hunter from
/// killing newborn workers.
pub fn classify_stuck(meta: &ProcessMeta, thresholds: &StuckThresholds) -> bool {
    meta.runtime >= thresholds.min_runtime && meta.cpu_pct < thresholds.idle_cpu_pct
}

/// Operator-readable hint string for one classified-stuck process.
/// Returned as `&'static str` so the hint never allocates per
/// process — useful when a scan finds dozens of stuck workers.
pub fn stuck_hint() -> &'static str {
    // GOLD-WIRE-05: references only real, shipped recovery. `neoth doctor`
    // now surfaces this as a WARN check (see cli/doctor.rs); the kill is
    // manual. The earlier copy named `neoth doctor stuck-clean` + `neoth
    // chat reset --force`, neither of which exists — removed so this string
    // is safe to display anywhere.
    "claude process is past the stuck threshold + idle CPU — likely \
     hung mid tool-call or waiting on a closed OAuth browser. `neoth \
     doctor` flags it as a WARN; after confirming it is not your active \
     foreground claude, kill the PID (`kill <pid>` on Unix, \
     `taskkill /PID <pid>` on Windows)."
}

/// Enumerate live processes via `sysinfo::System` + classify with
/// the operator's thresholds. Returns the descriptors for every
/// process that crossed both gates.
pub async fn scan_stuck_processes(thresholds: StuckThresholds) -> Vec<StuckProcess> {
    // sysinfo's refresh is synchronous + reasonably fast (~1ms for
    // a modest process table). Run via `spawn_blocking` so the
    // tokio reactor stays free for other timers.
    tokio::task::spawn_blocking(move || scan_blocking(thresholds))
        .await
        .unwrap_or_default()
}

/// GOLD-WIRE-05 — synchronous entry point for the `neoth doctor` check
/// registry. `run_all_checks` is a sync function (every diagnostic returns
/// its `CheckOutcome` directly), so it cannot `.await` the async
/// [`scan_stuck_processes`]. The `spawn_blocking` hop in the async variant
/// exists to keep the daemon's tokio reactor free; the one-shot `neoth
/// doctor` CLI has no such constraint, so it blocks its own calling thread
/// for the single process-table scan. Same `scan_blocking` core, same
/// classification — only the threading wrapper differs.
pub fn scan_stuck_processes_blocking(thresholds: StuckThresholds) -> Vec<StuckProcess> {
    scan_blocking(thresholds)
}

fn scan_blocking(thresholds: StuckThresholds) -> Vec<StuckProcess> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    // The second refresh gives a non-zero CPU% delta. sysinfo computes
    // cpu_usage() as (busy time / wall time) BETWEEN two refreshes — and
    // requires at least `MINIMUM_CPU_UPDATE_INTERVAL` (200ms on Win/Linux/
    // macOS) to elapse, or it reports ~0% for every process. Without the
    // sleep, two back-to-back refreshes leave a microsecond window → every
    // long-running claude reads 0% CPU → false-flagged as stuck. Sleeping
    // the platform minimum makes the reading real. This is off the tokio
    // reactor: the async entry wraps `scan_blocking` in `spawn_blocking`,
    // and the `neoth doctor` CLI blocks only its own (otherwise idle) thread.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut out = Vec::new();
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_string();
        if !is_claude_process_name(&name) {
            continue;
        }
        let meta = ProcessMeta {
            pid: pid.as_u32(),
            name,
            runtime: Duration::from_secs(proc_.run_time()),
            cpu_pct: proc_.cpu_usage(),
        };
        if classify_stuck(&meta, &thresholds) {
            out.push(StuckProcess {
                meta,
                thresholds,
                hint: stuck_hint(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, runtime: u64, cpu: f32) -> ProcessMeta {
        ProcessMeta {
            pid: 1,
            name: name.into(),
            runtime: Duration::from_secs(runtime),
            cpu_pct: cpu,
        }
    }

    #[test]
    fn default_thresholds_match_bridge_py() {
        let t = StuckThresholds::default();
        assert_eq!(t.min_runtime, Duration::from_secs(15 * 60));
        assert!((t.idle_cpu_pct - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn claude_process_names_pinned() {
        assert_eq!(CLAUDE_PROCESS_NAMES, &["claude", "claude-cli"]);
    }

    #[test]
    fn is_claude_process_name_matches_canonical_form() {
        assert!(is_claude_process_name("claude"));
        assert!(is_claude_process_name("claude-cli"));
    }

    #[test]
    fn is_claude_process_name_matches_uppercase_on_windows() {
        assert!(is_claude_process_name("Claude"));
        assert!(is_claude_process_name("CLAUDE"));
    }

    #[test]
    fn is_claude_process_name_strips_dot_exe() {
        assert!(is_claude_process_name("claude.exe"));
        assert!(is_claude_process_name("Claude.exe"));
    }

    #[test]
    fn is_claude_process_name_rejects_lookalikes() {
        assert!(!is_claude_process_name("claude-helper"));
        assert!(!is_claude_process_name("claudine"));
        assert!(!is_claude_process_name("not-claude"));
        assert!(!is_claude_process_name(""));
    }

    // ── classify_stuck ──────────────────────────────────────────

    #[test]
    fn classify_flags_long_idle_process() {
        let m = meta("claude", 16 * 60, 0.2);
        assert!(classify_stuck(&m, &StuckThresholds::default()));
    }

    #[test]
    fn classify_lets_busy_long_process_pass() {
        // Long runtime but still using CPU → not stuck.
        let m = meta("claude", 16 * 60, 25.0);
        assert!(!classify_stuck(&m, &StuckThresholds::default()));
    }

    #[test]
    fn classify_lets_newly_spawned_process_pass() {
        // Idle CPU but only 1min runtime → newborn, not stuck.
        let m = meta("claude", 60, 0.0);
        assert!(!classify_stuck(&m, &StuckThresholds::default()));
    }

    #[test]
    fn classify_respects_custom_thresholds() {
        let custom = StuckThresholds {
            min_runtime: Duration::from_secs(60),
            idle_cpu_pct: 5.0,
        };
        let m = meta("claude", 90, 3.0);
        assert!(classify_stuck(&m, &custom));
    }

    #[test]
    fn classify_uses_strict_less_than_on_cpu() {
        // CPU exactly at threshold is NOT stuck — give borderline
        // processes the benefit of the doubt.
        let t = StuckThresholds {
            min_runtime: Duration::from_secs(0),
            idle_cpu_pct: 1.0,
        };
        let m = meta("claude", 9999, 1.0);
        assert!(!classify_stuck(&m, &t));
    }

    #[test]
    fn stuck_hint_points_at_real_recovery_only() {
        let h = stuck_hint();
        // Operator must see WHERE to act. Pin so a future re-word
        // doesn't drop the recovery pointer.
        assert!(h.contains("neoth doctor"));
        assert!(h.to_ascii_lowercase().contains("kill"));
        // GOLD-WIRE-05 honesty guard: the hint must NOT name commands that
        // don't exist. This flips the old test (which PINNED the phantom
        // `neoth chat reset`) into a guard against re-introducing them.
        assert!(
            !h.contains("stuck-clean"),
            "stuck_hint references the unbuilt `neoth doctor stuck-clean`"
        );
        assert!(
            !h.contains("chat reset"),
            "stuck_hint references the unbuilt `neoth chat reset`"
        );
    }

    #[tokio::test]
    async fn scan_stuck_processes_returns_no_panic_on_quiet_host() {
        // Smoke test — the host running this test may or may not
        // have any `claude` processes alive. Either way the scan
        // must not panic + must return a Vec (possibly empty).
        let stuck = scan_stuck_processes(StuckThresholds::default()).await;
        // Sanity: every entry meets BOTH gates.
        let t = StuckThresholds::default();
        for s in &stuck {
            assert!(classify_stuck(&s.meta, &t));
            assert!(!s.hint.is_empty());
        }
    }
}
