//! EL-01 — `neoth doctor` cron + actionable findings + WAL audit.
//!
//! The existing `cli::doctor::run_all_checks` is one-shot. EL-01
//! wraps it for the cron path:
//!
//!   - Periodic [`DoctorCronTask::tick`] runs the suite + builds
//!     a [`DoctorCronReport`].
//!   - Each `CheckOutcome` is enriched with an [`ActionableFinding`]
//!     carrying a `runbook_id` + `suggested_command` the operator
//!     can copy-paste.
//!   - The reporter renders Warn/Fail findings as a chat-ready
//!     notification line + a JSON payload for the WAL audit
//!     emit-site.
//!
//! ## Why a separate module
//!
//! `cli::doctor` already owns the diagnostic surface. EL-01 is the
//! "what to DO with the outcomes" half — splitting it keeps the
//! diagnostic catalogue (`CHECK_DOCS`) cleanly separated from the
//! cron orchestration + actionability mapping.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cli::doctor::{CheckOutcome, CheckStatus};

/// Default cron interval — operators tune via
/// `freedom.yaml::doctor.cron_interval_secs`. 1 hour balances
/// "noticeable when the wizard hasn't run for ages" against "not
/// hammering the operator's machine".
pub const DEFAULT_CRON_INTERVAL_SECS: u64 = 3600;

/// One operator-actionable finding paired with the underlying
/// CheckOutcome. `runbook_id` lets future PROGRESS entries link
/// to the diagnostic class without re-keying on free-text names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionableFinding {
    /// Same `name` as the `CheckOutcome`.
    pub check_name: String,
    /// Status (passed through verbatim).
    pub status: String,
    /// Diagnostic text from the check.
    pub detail: String,
    /// Stable ID an operator can grep for in the runbook docs
    /// (`"home_isolation"`, `"wal_dpapi"`, `"missing_freedom_yaml"`,
    /// …). Derived deterministically from `check_name` via
    /// [`runbook_id_for`].
    pub runbook_id: String,
    /// Operator-visible command they can copy-paste to fix the
    /// finding, when one applies. Empty when the runbook says
    /// "manual investigation needed".
    pub suggested_command: String,
    /// One-line summary suitable for the proactive-channel
    /// notification ("FAIL: home isolation — run `neoth doctor
    /// --fix`").
    pub one_line: String,
}

/// Full report from one cron pass. Emit-site writes this as a
/// JSON payload + a `0x4? DOCTOR_TICK` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCronReport {
    pub ts_unix: i64,
    pub total_checks: usize,
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    /// Every finding (PASS included) — auditor decides whether to
    /// surface noise. The reporter's chat-notification surface
    /// filters to Warn+Fail.
    pub findings: Vec<ActionableFinding>,
}

impl DoctorCronReport {
    /// True when nothing failed AND nothing warned — pass-only
    /// pass. Chat-notification path skips these so operators
    /// don't see hourly "everything fine" pings.
    pub fn is_clean(&self) -> bool {
        self.warn_count == 0 && self.fail_count == 0
    }

    /// Findings the operator should see in the chat / GUI notice
    /// — Warn + Fail. Pass entries stay in the WAL but don't
    /// surface as a notification.
    pub fn actionable_findings(&self) -> Vec<&ActionableFinding> {
        self.findings
            .iter()
            .filter(|f| f.status == "WARN" || f.status == "FAIL")
            .collect()
    }
}

/// Map a CheckOutcome's name to a stable runbook id. Pure-fn.
/// Returns the snake_case name itself when no special-case
/// applies — same shape grep-able from PROGRESS.
pub fn runbook_id_for(check_name: &str) -> String {
    check_name
        .to_lowercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        .trim_matches('_')
        .to_string()
}

/// Build the operator-facing suggested command for a check.
/// Returns empty when no canonical fix exists (operator runs
/// `neoth doctor --check <id>` to re-read the runbook).
pub fn suggested_command_for(check_name: &str, status: &CheckStatus) -> String {
    if matches!(status, CheckStatus::Pass) {
        return String::new();
    }
    let id = runbook_id_for(check_name);
    // Pinned mapping of canonical fix commands. Adding a new
    // mapping = one line here + a runbook entry under
    // `cli::doctor::CHECK_DOCS`.
    match id.as_str() {
        // Home directory permissions — operator runs the
        // `neoth doctor --fix-home-perms` helper.
        "home_isolation" => "neoth doctor --fix-home-perms".to_string(),
        // Missing freedom.yaml — re-run init.
        "freedom_yaml" | "missing_freedom_yaml" => "neoth init".to_string(),
        // Stale WAL credentials → re-issue.
        "wal_dpapi" | "credential_age" => "neoth credentials rotate".to_string(),
        // No canonical fix — operator re-reads the runbook entry.
        _ => format!("neoth doctor --check {id}"),
    }
}

/// Project a CheckOutcome into an ActionableFinding. Pure-fn.
pub fn enrich_outcome(outcome: &CheckOutcome) -> ActionableFinding {
    let runbook_id = runbook_id_for(outcome.name);
    let suggested = suggested_command_for(outcome.name, &outcome.status);
    let tag = outcome.status.tag();
    let one_line = if suggested.is_empty() {
        format!("{tag}: {} — {}", outcome.name, outcome.detail)
    } else {
        format!(
            "{tag}: {} — {} (try: `{}`)",
            outcome.name, outcome.detail, suggested,
        )
    };
    ActionableFinding {
        check_name: outcome.name.to_string(),
        status: tag.to_string(),
        detail: outcome.detail.clone(),
        runbook_id,
        suggested_command: suggested,
        one_line,
    }
}

/// Build the full cron report from a CheckOutcome list.
pub fn build_report(ts_unix: i64, outcomes: &[CheckOutcome]) -> DoctorCronReport {
    let findings: Vec<ActionableFinding> = outcomes.iter().map(enrich_outcome).collect();
    let pass_count = outcomes
        .iter()
        .filter(|o| matches!(o.status, CheckStatus::Pass))
        .count();
    let warn_count = outcomes
        .iter()
        .filter(|o| matches!(o.status, CheckStatus::Warn))
        .count();
    let fail_count = outcomes
        .iter()
        .filter(|o| matches!(o.status, CheckStatus::Fail))
        .count();
    DoctorCronReport {
        ts_unix,
        total_checks: outcomes.len(),
        pass_count,
        warn_count,
        fail_count,
        findings,
    }
}

/// Render the chat-notification body for a non-clean report.
/// Returns empty when the report is clean — caller short-circuits.
pub fn render_chat_notification(report: &DoctorCronReport) -> String {
    if report.is_clean() {
        return String::new();
    }
    let mut out = String::new();
    if report.fail_count > 0 {
        out.push_str(&format!(
            "neoth doctor: {} FAIL / {} WARN out of {} checks\n",
            report.fail_count, report.warn_count, report.total_checks,
        ));
    } else {
        out.push_str(&format!(
            "neoth doctor: {} WARN out of {} checks\n",
            report.warn_count, report.total_checks,
        ));
    }
    for f in report.actionable_findings() {
        out.push_str(&format!("  • {}\n", f.one_line));
    }
    out
}

/// Operator-config for the cron task. Today's slice ships the
/// data shape; the actual cron-loop wiring lands when EL-01b
/// integrates with the existing `cron` scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCronConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Notification channel name (`"cli"` / `"telegram"` / …).
    /// Empty = no proactive chat notification, but WAL emit still
    /// fires.
    pub notify_channel: String,
}

impl Default for DoctorCronConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_CRON_INTERVAL_SECS,
            notify_channel: "cli".to_string(),
        }
    }
}

impl DoctorCronConfig {
    /// Interval as a Duration. Clamped to 60s minimum so a
    /// misconfigured 0 doesn't tight-loop.
    pub fn interval_duration(&self) -> Duration {
        Duration::from_secs(self.interval_secs.max(60))
    }
}

// ── EL-01 runtime: cron loop + WAL emit + notification sink ────────────────────

/// Pluggable sink for the chat-notification half of a non-clean
/// doctor report. Trait-object boxed in the spawn helper so the
/// daemon can register the operator's preferred channel
/// (`cli` → tracing logs, `sidecar` → JSON file the GUI polls,
/// future `telegram` / `keet` → real channel push). The trait is
/// async so a future Telegram impl can `await` its HTTP send
/// without blocking the cron loop.
#[async_trait::async_trait]
pub trait DoctorNotificationSink: Send + Sync {
    /// Deliver the non-clean report body. Returning `Err` is
    /// non-fatal — the cron loop logs + continues. Empty `body`
    /// (clean report) is never passed to `notify`.
    async fn notify(&self, body: String) -> Result<(), String>;
}

/// Default sink — emits the non-clean report via `tracing::warn`.
/// Operators who run without a configured GUI / channel still see
/// the doctor's voice in their journalctl / `neoth serve` logs.
pub struct TracingNotificationSink;

#[async_trait::async_trait]
impl DoctorNotificationSink for TracingNotificationSink {
    async fn notify(&self, body: String) -> Result<(), String> {
        tracing::warn!(target: "neoth::doctor_cron", "doctor finding\n{body}");
        Ok(())
    }
}

/// Sidecar sink — writes the rendered notification body + the
/// raw report JSON to `<dir>/doctor_<ts_unix>.json`. The GUI's
/// notifications panel + future channel push subscribers poll the
/// directory + render entries to the operator. The file write is
/// atomic via `.tmp` + rename (same pattern as the rest of NEOTH's
/// on-disk persistence) so a partially-written file is never
/// observed.
pub struct SidecarNotificationSink {
    pub dir: std::path::PathBuf,
}

impl SidecarNotificationSink {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn record_path(&self, ts_unix: i64) -> std::path::PathBuf {
        self.dir.join(format!("doctor_{ts_unix}.json"))
    }
}

#[async_trait::async_trait]
impl DoctorNotificationSink for SidecarNotificationSink {
    async fn notify(&self, body: String) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("mkdir: {e}"))?;
        let ts_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let final_path = self.record_path(ts_unix);
        let tmp_path = final_path.with_extension("json.tmp");
        let payload = serde_json::json!({
            "ts_unix": ts_unix,
            "body": body,
        });
        let serialised = serde_json::to_vec_pretty(&payload).map_err(|e| format!("serde: {e}"))?;
        std::fs::write(&tmp_path, &serialised).map_err(|e| format!("write tmp: {e}"))?;
        // Windows-safe rename: remove the target first if it exists
        // (Windows refuses rename-over-existing).
        if final_path.exists() {
            let _ = std::fs::remove_file(&final_path);
        }
        std::fs::rename(&tmp_path, &final_path).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }
}

/// One cron pass. Pure-fn over the home dir: runs the diagnostic
/// suite, builds the report, emits the WAL frame, and (when not
/// clean) hands the rendered notification body to the sink. Exposed
/// for unit-testing so an integration test can verify the WAL
/// frame + sidecar drop without spinning up the full tokio loop.
pub async fn run_doctor_tick(
    home: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
    sink: &dyn DoctorNotificationSink,
) -> Result<DoctorCronReport, String> {
    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // run_all_checks is sync and blocks (check_stuck_claude_processes
    // sleeps 200ms; several checks do file/registry IO) — run it on the
    // blocking pool so the daemon's reactor keeps ticking.
    let home_owned = home.to_path_buf();
    let outcomes =
        tokio::task::spawn_blocking(move || crate::cli::doctor::run_all_checks(&home_owned))
            .await
            .map_err(|e| format!("doctor checks panicked: {e}"))?;
    let report = build_report(ts_unix, &outcomes);

    // WAL emit — every tick, clean or not. The audit chain proves
    // the cron ran, not just "the cron ran AND found things".
    let payload = serde_json::to_vec(&report).map_err(|e| format!("serde report: {e}"))?;
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_DOCTOR_TICK, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
    writer
        .append(header, payload)
        .await
        .map_err(|e| format!("wal append: {e}"))?;

    // Notification path — only for Warn/Fail reports.
    if !report.is_clean() {
        let body = render_chat_notification(&report);
        if let Err(e) = sink.notify(body).await {
            tracing::warn!(error = %e, "doctor notification sink failed");
        }
    }
    Ok(report)
}

/// Spawn the cron loop. Returns the JoinHandle so the daemon can
/// track it alongside the other background tasks. Drop the handle
/// to cancel cleanly. When `config.enabled == false` the function
/// returns immediately with `None` so the daemon doesn't accumulate
/// idle tokio tasks.
pub fn spawn_doctor_cron_loop(
    config: DoctorCronConfig,
    home: std::path::PathBuf,
    writer: crate::wal::writer::WalWriterHandle,
    sink: std::sync::Arc<dyn DoctorNotificationSink>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("doctor cron disabled in config; skipping loop spawn");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            "doctor cron loop online (EL-01)",
        );
        loop {
            ticker.tick().await;
            match run_doctor_tick(&home, &writer, sink.as_ref()).await {
                Ok(report) => {
                    tracing::debug!(
                        pass = report.pass_count,
                        warn = report.warn_count,
                        fail = report.fail_count,
                        "doctor tick complete",
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "doctor tick failed");
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(name: &'static str, status: CheckStatus, detail: &str) -> CheckOutcome {
        CheckOutcome {
            name,
            status,
            detail: detail.to_string(),
        }
    }

    // ── runbook_id_for ────────────────────────────────────────────

    #[test]
    fn runbook_id_lowercases_and_snake_cases() {
        assert_eq!(runbook_id_for("Home Isolation"), "home_isolation");
        assert_eq!(runbook_id_for("WAL DPAPI"), "wal_dpapi");
        assert_eq!(
            runbook_id_for("freedom.yaml present"),
            "freedom_yaml_present"
        );
    }

    #[test]
    fn runbook_id_collapses_non_alphanumeric_runs() {
        assert_eq!(runbook_id_for("a/b\\c-d e"), "a_b_c_d_e");
    }

    #[test]
    fn runbook_id_trims_leading_and_trailing_underscores() {
        assert_eq!(runbook_id_for("--alpha--"), "alpha");
    }

    // ── suggested_command_for ─────────────────────────────────────

    #[test]
    fn pass_status_returns_empty_suggested_command() {
        assert!(suggested_command_for("anything", &CheckStatus::Pass).is_empty());
    }

    #[test]
    fn home_isolation_maps_to_fix_home_perms() {
        let cmd = suggested_command_for("home_isolation", &CheckStatus::Fail);
        assert_eq!(cmd, "neoth doctor --fix-home-perms");
    }

    #[test]
    fn freedom_yaml_maps_to_init() {
        assert_eq!(
            suggested_command_for("freedom_yaml", &CheckStatus::Fail),
            "neoth init",
        );
    }

    #[test]
    fn wal_dpapi_maps_to_credentials_rotate() {
        assert_eq!(
            suggested_command_for("wal_dpapi", &CheckStatus::Fail),
            "neoth credentials rotate",
        );
    }

    #[test]
    fn unknown_check_falls_back_to_doctor_check_runbook() {
        let cmd = suggested_command_for("brand_new_check", &CheckStatus::Warn);
        assert_eq!(cmd, "neoth doctor --check brand_new_check");
    }

    // ── enrich_outcome ────────────────────────────────────────────

    #[test]
    fn enrich_pass_outcome_has_empty_suggested_command() {
        let o = outcome("home_isolation", CheckStatus::Pass, "ok");
        let f = enrich_outcome(&o);
        assert_eq!(f.status, "PASS");
        assert!(f.suggested_command.is_empty());
        assert!(!f.one_line.contains("try:"));
    }

    #[test]
    fn enrich_fail_outcome_includes_try_hint() {
        let o = outcome("home_isolation", CheckStatus::Fail, "g+r leaked");
        let f = enrich_outcome(&o);
        assert_eq!(f.status, "FAIL");
        assert_eq!(f.runbook_id, "home_isolation");
        assert_eq!(f.suggested_command, "neoth doctor --fix-home-perms");
        assert!(f.one_line.contains("FAIL"));
        assert!(f.one_line.contains("home_isolation"));
        assert!(f.one_line.contains("g+r leaked"));
        assert!(f.one_line.contains("neoth doctor --fix-home-perms"));
    }

    #[test]
    fn enrich_warn_outcome_includes_try_hint() {
        let o = outcome("custom_check", CheckStatus::Warn, "noisy disk");
        let f = enrich_outcome(&o);
        assert_eq!(f.status, "WARN");
        assert!(f.one_line.contains("WARN"));
        assert!(f.one_line.contains("(try:"));
    }

    // ── build_report ──────────────────────────────────────────────

    #[test]
    fn report_counters_partition_outcomes() {
        let r = build_report(
            100,
            &[
                outcome("a", CheckStatus::Pass, "ok"),
                outcome("b", CheckStatus::Pass, "ok"),
                outcome("c", CheckStatus::Warn, "noisy"),
                outcome("d", CheckStatus::Fail, "broken"),
            ],
        );
        assert_eq!(r.total_checks, 4);
        assert_eq!(r.pass_count, 2);
        assert_eq!(r.warn_count, 1);
        assert_eq!(r.fail_count, 1);
        assert_eq!(r.findings.len(), 4);
        assert_eq!(r.ts_unix, 100);
    }

    #[test]
    fn report_is_clean_when_no_warn_or_fail() {
        let r = build_report(
            100,
            &[
                outcome("a", CheckStatus::Pass, "ok"),
                outcome("b", CheckStatus::Pass, "ok"),
            ],
        );
        assert!(r.is_clean());
    }

    #[test]
    fn report_not_clean_with_any_warn() {
        let r = build_report(100, &[outcome("a", CheckStatus::Warn, "x")]);
        assert!(!r.is_clean());
    }

    #[test]
    fn report_not_clean_with_any_fail() {
        let r = build_report(100, &[outcome("a", CheckStatus::Fail, "x")]);
        assert!(!r.is_clean());
    }

    #[test]
    fn actionable_findings_filters_to_warn_and_fail() {
        let r = build_report(
            100,
            &[
                outcome("a", CheckStatus::Pass, "ok"),
                outcome("b", CheckStatus::Warn, "noisy"),
                outcome("c", CheckStatus::Fail, "broken"),
            ],
        );
        let actionable = r.actionable_findings();
        assert_eq!(actionable.len(), 2);
        assert!(actionable.iter().any(|f| f.check_name == "b"));
        assert!(actionable.iter().any(|f| f.check_name == "c"));
        assert!(!actionable.iter().any(|f| f.check_name == "a"));
    }

    // ── render_chat_notification ──────────────────────────────────

    #[test]
    fn render_clean_report_returns_empty_string() {
        let r = build_report(100, &[outcome("a", CheckStatus::Pass, "ok")]);
        assert!(render_chat_notification(&r).is_empty());
    }

    #[test]
    fn render_fail_includes_fail_count_header() {
        let r = build_report(
            100,
            &[
                outcome("a", CheckStatus::Fail, "broken"),
                outcome("b", CheckStatus::Warn, "noisy"),
            ],
        );
        let msg = render_chat_notification(&r);
        assert!(msg.contains("1 FAIL"));
        assert!(msg.contains("1 WARN"));
        assert!(msg.contains("• FAIL:"));
        assert!(msg.contains("• WARN:"));
    }

    #[test]
    fn render_warn_only_omits_fail_count() {
        let r = build_report(100, &[outcome("a", CheckStatus::Warn, "noisy")]);
        let msg = render_chat_notification(&r);
        assert!(msg.contains("1 WARN"));
        assert!(!msg.contains("FAIL"));
    }

    // ── DoctorCronConfig ──────────────────────────────────────────

    #[test]
    fn default_config_pinned() {
        let c = DoctorCronConfig::default();
        assert!(c.enabled);
        assert_eq!(c.interval_secs, DEFAULT_CRON_INTERVAL_SECS);
        assert_eq!(c.notify_channel, "cli");
    }

    #[test]
    fn interval_clamped_to_60_seconds_minimum() {
        let c = DoctorCronConfig {
            enabled: true,
            interval_secs: 5,
            notify_channel: String::new(),
        };
        assert_eq!(c.interval_duration(), Duration::from_secs(60));
    }

    #[test]
    fn interval_uses_configured_value_above_floor() {
        let c = DoctorCronConfig {
            enabled: true,
            interval_secs: 7200,
            notify_channel: String::new(),
        };
        assert_eq!(c.interval_duration(), Duration::from_secs(7200));
    }

    // ── serde ─────────────────────────────────────────────────────

    #[test]
    fn report_serde_roundtrip() {
        let r = build_report(
            42,
            &[
                outcome("home_isolation", CheckStatus::Fail, "g+r leaked"),
                outcome("freedom_yaml", CheckStatus::Pass, "ok"),
            ],
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: DoctorCronReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn finding_serialises_snake_case_audit_keys() {
        let f = enrich_outcome(&outcome("home_isolation", CheckStatus::Fail, "leak"));
        let json = serde_json::to_string(&f).unwrap();
        for key in [
            "check_name",
            "status",
            "detail",
            "runbook_id",
            "suggested_command",
            "one_line",
        ] {
            assert!(json.contains(&format!("\"{key}\"")), "missing key {key}");
        }
    }

    // ── SidecarNotificationSink ───────────────────────────────────

    #[tokio::test]
    async fn sidecar_sink_writes_file_with_body() {
        let dir = tempfile::tempdir().unwrap();
        let sink = SidecarNotificationSink::new(dir.path());
        sink.notify("doctor saw 1 FAIL".to_string()).await.unwrap();
        let mut entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read_to_string(entries.pop().unwrap().path()).unwrap();
        assert!(body.contains("doctor saw 1 FAIL"));
        assert!(body.contains("ts_unix"));
        // Drift guard: tmp companion must NOT remain after the atomic rename.
        assert!(
            !std::fs::read_dir(dir.path()).unwrap().any(|e| e
                .unwrap()
                .path()
                .to_string_lossy()
                .ends_with(".tmp")),
        );
    }

    #[tokio::test]
    async fn tracing_sink_returns_ok_for_any_body() {
        let sink = TracingNotificationSink;
        assert!(sink.notify("anything".to_string()).await.is_ok());
    }

    // ── run_doctor_tick — WAL frame + sink invocation ─────────────

    /// Recording sink — captures every notify body for assertions.
    struct RecordingSink {
        captured: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn bodies(&self) -> Vec<String> {
            self.captured.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DoctorNotificationSink for RecordingSink {
        async fn notify(&self, body: String) -> Result<(), String> {
            self.captured.lock().unwrap().push(body);
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_doctor_tick_writes_wal_frame_and_returns_report() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("doctor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let sink = RecordingSink::new();
        let report = run_doctor_tick(home.path(), &writer, &sink).await.unwrap();
        assert!(report.total_checks > 0, "expected at least one check");
        // WAL file must exist + be non-empty after the append.
        let meta = std::fs::metadata(&seg).unwrap();
        assert!(meta.len() > 0, "WAL file empty after doctor tick");
    }

    #[tokio::test]
    async fn run_doctor_tick_does_not_notify_on_clean_report() {
        // A fresh tempdir HOME means most checks WARN/FAIL (no
        // freedom.yaml etc.) — so this test exercises the
        // not-clean branch. The matching clean branch is asserted
        // via the unit-level `render_chat_notification` returning
        // empty on clean (already covered above) + the explicit
        // is_clean short-circuit in run_doctor_tick.
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("doctor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let sink = RecordingSink::new();
        let report = run_doctor_tick(home.path(), &writer, &sink).await.unwrap();
        // Either: report is not clean → exactly one notify body.
        // Or: report is clean → zero bodies.
        if report.is_clean() {
            assert!(sink.bodies().is_empty());
        } else {
            assert_eq!(sink.bodies().len(), 1);
            assert!(!sink.bodies()[0].is_empty());
        }
    }

    // ── spawn_doctor_cron_loop ────────────────────────────────────

    #[tokio::test]
    async fn spawn_loop_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("doctor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = DoctorCronConfig {
            enabled: false,
            interval_secs: DEFAULT_CRON_INTERVAL_SECS,
            notify_channel: "cli".into(),
        };
        let sink: std::sync::Arc<dyn DoctorNotificationSink> =
            std::sync::Arc::new(TracingNotificationSink);
        let handle = spawn_doctor_cron_loop(cfg, home.path().to_path_buf(), writer, sink);
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_loop_returns_some_when_enabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("doctor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = DoctorCronConfig::default();
        let sink: std::sync::Arc<dyn DoctorNotificationSink> =
            std::sync::Arc::new(TracingNotificationSink);
        let handle = spawn_doctor_cron_loop(cfg, home.path().to_path_buf(), writer, sink);
        let handle = handle.expect("expected join handle when enabled");
        handle.abort(); // immediate cancel; ticker has not even fired yet
    }
}
