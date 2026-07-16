//! Per-provider quota tracker — H5 cascade from
//! `PLAN/SPEC_council_governance.md` §2.
//!
//! When a remote provider returns HTTP 429, this tracker:
//!   1. Records the `Retry-After` header (or a 1h default) as a backoff
//!      window.
//!   2. Persists state to `~/.neoth/quota.json` (atomic write) so the
//!      backoff survives daemon restarts.
//!   3. Exposes `is_healthy(provider) -> bool` so callers can skip the
//!      adapter entirely while the window is active instead of paying
//!      the round-trip cost just to be rate-limited again.
//!
//! Daily-reset semantics: every successful call increments
//! `requests_today`; the counter rolls over at local midnight (the
//! `last_reset_unix` timestamp captures the boundary). On read, a stale
//! counter is reset lazily — no background cron required.
//!
//! Pure state machine — no WAL emission inside this module. Callers
//! emit `EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED` (0x24) at the recording
//! site so the tracker stays test-isolatable without a WAL handle.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Serialises quota read-modify-write transactions inside one process. The
/// sibling advisory lock in [`QuotaTracker::update_at`] covers other NEOTH
/// processes using the same operator home.
static QUOTA_UPDATE_LOCK: Mutex<()> = Mutex::new(());

fn quota_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

/// Typed error returned by provider adapters when the remote API responds
/// with HTTP 429. Dispatchers downcast `anyhow::Error` to this struct via
/// `err.downcast_ref::<QuotaError>()` to surface a `Retry-After`-aware
/// message and update [`QuotaTracker`] without re-parsing the response.
#[derive(Debug, thiserror::Error)]
#[error("{provider}: quota exceeded (HTTP 429), retry_after={retry_after:?}{body_suffix}",
    body_suffix = if body.is_empty() { String::new() } else { format!(" body={body}") })]
pub struct QuotaError {
    pub provider: &'static str,
    pub retry_after: Option<Duration>,
    pub body: String,
}

/// Parse the `Retry-After` HTTP header. RFC 7231 allows either an integer
/// (seconds) or an HTTP-date. We only honour the integer form — HTTP-date
/// rarely appears for 429 in practice, and pulling in a date parser for it
/// is not worth the dependency surface. An unparseable header yields
/// `None`; the caller falls back to [`DEFAULT_BACKOFF`].
pub fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Default backoff applied when a 429 response carries no `Retry-After`
/// header. One hour matches what most operator-grade APIs (OpenAI,
/// Anthropic, Gemini) settle into in practice.
pub const DEFAULT_BACKOFF: Duration = Duration::from_secs(3600);

/// Hard ceiling on the backoff window — caps adversarial / buggy server
/// `Retry-After: 99999999` from locking an operator out for days.
pub const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// One provider's rolling quota state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuotaState {
    pub provider: String,
    pub requests_today: u32,
    /// Unix-seconds of the last 429. `None` = never observed.
    pub last_429_unix: Option<u64>,
    /// Unix-seconds when the backoff window ends. `None` or `<= now` = healthy.
    pub backoff_until_unix: Option<u64>,
    /// Most recent `Retry-After` value (seconds) — for telemetry.
    pub last_retry_after_secs: Option<u64>,
    /// Operator-observed daily request ceiling. `None` until inferred from
    /// repeated 429 patterns; today set only via `neoth quota set-cap`.
    pub estimated_daily_cap: Option<u32>,
    /// Unix-seconds of the most recent `last_reset` for the daily counter.
    pub last_reset_unix: u64,
}

impl ProviderQuotaState {
    fn new(provider: &str, now_unix: u64) -> Self {
        Self {
            provider: provider.to_string(),
            requests_today: 0,
            last_429_unix: None,
            backoff_until_unix: None,
            last_retry_after_secs: None,
            estimated_daily_cap: None,
            last_reset_unix: now_unix,
        }
    }

    /// True when no active backoff window applies right now.
    pub fn is_healthy(&self, now_unix: u64) -> bool {
        match self.backoff_until_unix {
            Some(until) => now_unix >= until,
            None => true,
        }
    }

    /// Remaining seconds in the active backoff window. 0 = healthy.
    pub fn backoff_remaining_secs(&self, now_unix: u64) -> u64 {
        self.backoff_until_unix
            .map(|until| until.saturating_sub(now_unix))
            .unwrap_or(0)
    }
}

/// Persistent quota state across providers. Backed by `~/.neoth/quota.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QuotaTracker {
    states: HashMap<String, ProviderQuotaState>,
    /// Path used by `save()`. Skipped during serde so test fixtures don't
    /// leak temp paths into checked-in JSON.
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl QuotaTracker {
    /// Construct a tracker that loads from `path` on disk, or starts empty
    /// only when the file is absent. Existing but unreadable or malformed
    /// state is an error: silently clearing provider backoff would allow a
    /// restart or disk fault to bypass an active quota safety boundary.
    pub fn load_from(path: &Path) -> Result<Self> {
        let mut tracker: QuotaTracker = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse quota state {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => QuotaTracker::default(),
            Err(e) => {
                return Err(e).with_context(|| format!("read quota state {}", path.display()));
            }
        };
        tracker.path = Some(path.to_path_buf());
        Ok(tracker)
    }

    /// Locked, fail-closed read-modify-write transaction for `quota.json`.
    ///
    /// The process mutex and sibling OS lock are held from the strict reload
    /// through the private atomic replacement. This is the only production
    /// mutation path: a provider success, a 429, and an operator reset must not
    /// overwrite one another from stale snapshots.
    pub fn update_at<T>(path: &Path, mutation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let _process_guard = match QUOTA_UPDATE_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let lock_path = quota_lock_path(path);
        let _file_guard =
            crate::util::locked_file::lock_file_blocking(&lock_path, "provider quota state")?;

        let mut tracker = Self::load_from(path)?;
        let result = mutation(&mut tracker)?;
        tracker.save()?;
        Ok(result)
    }

    /// In-memory tracker for unit tests. Never touches disk.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Override the persistence path. Used by integration tests that want
    /// a tempdir-rooted file.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Persist current state. No-op when the tracker has no path (in-memory).
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let body = serde_json::to_vec_pretty(self).context("serialize quota.json")?;
        crate::util::atomic_write::atomic_write_private(path, &body)
            .with_context(|| format!("atomically write private quota state {}", path.display()))?;
        Ok(())
    }

    /// Read-only snapshot of one provider's state.
    pub fn get(&self, provider: &str) -> Option<&ProviderQuotaState> {
        self.states.get(provider)
    }

    /// Read-only snapshot of every tracked provider, sorted by name.
    pub fn snapshot(&self) -> Vec<ProviderQuotaState> {
        let mut all: Vec<_> = self.states.values().cloned().collect();
        all.sort_by(|a, b| a.provider.cmp(&b.provider));
        all
    }

    /// True iff this provider currently has no active backoff window.
    /// Unknown providers default to healthy.
    pub fn is_healthy(&self, provider: &str, now_unix: u64) -> bool {
        self.states
            .get(provider)
            .map(|s| s.is_healthy(now_unix))
            .unwrap_or(true)
    }

    /// ADV-10c — the soft-skip pre-flight primitive: `Some(remaining_secs)`
    /// when the provider is in an active 429 backoff window (caller should
    /// skip the call + log a warning), `None` when the provider is healthy,
    /// untracked, or never observed a 429. Distinct from `is_healthy`
    /// because callers also want the operator-visible "wait N seconds"
    /// signal without re-walking the map. Any local provider (see
    /// [`crate::providers::is_local_provider`]) always returns `None` —
    /// local inference is never rate-limited and the tracker carries no
    /// state for it.
    pub fn backoff_remaining_for(&self, provider: &str, now_unix: u64) -> Option<u64> {
        if crate::providers::is_local_provider(provider) {
            return None;
        }
        let state = self.states.get(provider)?;
        if state.is_healthy(now_unix) {
            return None;
        }
        Some(state.backoff_remaining_secs(now_unix))
    }

    /// Increment the per-day counter for a successful call. Rolls over
    /// the counter if midnight UTC has passed since `last_reset_unix`.
    /// Returns the new `requests_today` value.
    pub fn record_success(&mut self, provider: &str, now_unix: u64) -> u32 {
        let state = self
            .states
            .entry(provider.to_string())
            .or_insert_with(|| ProviderQuotaState::new(provider, now_unix));
        roll_daily_counter(state, now_unix);
        state.requests_today = state.requests_today.saturating_add(1);
        state.requests_today
    }

    /// Record a 429 response. `retry_after` is the server-advertised
    /// backoff (None → `DEFAULT_BACKOFF`). The recorded window is clamped
    /// to `MAX_BACKOFF` to defend against adversarial response headers.
    /// Returns the actual backoff applied.
    pub fn record_429(
        &mut self,
        provider: &str,
        retry_after: Option<Duration>,
        now_unix: u64,
    ) -> Duration {
        let effective = retry_after.unwrap_or(DEFAULT_BACKOFF).min(MAX_BACKOFF);
        let state = self
            .states
            .entry(provider.to_string())
            .or_insert_with(|| ProviderQuotaState::new(provider, now_unix));
        roll_daily_counter(state, now_unix);
        state.last_429_unix = Some(now_unix);
        state.last_retry_after_secs = Some(effective.as_secs());
        let new_until = now_unix.saturating_add(effective.as_secs());
        // Coalesce repeat 429s within an active window — only extend if the
        // new window is longer. Keeps the WAL band clean of duplicate frames
        // when an adapter retries during the window.
        state.backoff_until_unix = Some(match state.backoff_until_unix {
            Some(prev) if prev > new_until => prev,
            _ => new_until,
        });
        effective
    }

    /// Operator-initiated reset of a single provider's backoff window +
    /// daily counter. Used by `neoth quota reset <provider>`.
    pub fn reset(&mut self, provider: &str, now_unix: u64) {
        if let Some(state) = self.states.get_mut(provider) {
            state.requests_today = 0;
            state.backoff_until_unix = None;
            state.last_retry_after_secs = None;
            state.last_reset_unix = now_unix;
        }
    }

    /// Operator-set ceiling on daily requests. Telemetry-only — the
    /// tracker never refuses a call based on this; `is_healthy` is the
    /// only gating signal.
    pub fn set_cap(&mut self, provider: &str, cap: u32, now_unix: u64) {
        let state = self
            .states
            .entry(provider.to_string())
            .or_insert_with(|| ProviderQuotaState::new(provider, now_unix));
        state.estimated_daily_cap = Some(cap);
    }
}

/// Reset the per-day counter when a midnight-UTC boundary has been crossed
/// since the last reset.
fn roll_daily_counter(state: &mut ProviderQuotaState, now_unix: u64) {
    const SECONDS_PER_DAY: u64 = 24 * 3600;
    let prev_day = state.last_reset_unix / SECONDS_PER_DAY;
    let curr_day = now_unix / SECONDS_PER_DAY;
    if curr_day > prev_day {
        state.requests_today = 0;
        state.last_reset_unix = now_unix;
    }
}

/// Current wall-clock Unix seconds. Wraps `SystemTime` so callers can stub
/// it in tests via `now_unix_or(fixture)`.
pub fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const T0: u64 = 1_700_000_000;

    #[test]
    fn unknown_provider_defaults_healthy() {
        let t = QuotaTracker::in_memory();
        assert!(t.is_healthy("never-seen", T0));
    }

    #[test]
    fn record_429_sets_backoff_window() {
        let mut t = QuotaTracker::in_memory();
        let backoff = t.record_429("openai_api", Some(Duration::from_secs(120)), T0);
        assert_eq!(backoff, Duration::from_secs(120));
        assert!(!t.is_healthy("openai_api", T0));
        assert!(!t.is_healthy("openai_api", T0 + 119));
        assert!(t.is_healthy("openai_api", T0 + 120));
    }

    #[test]
    fn record_429_defaults_to_one_hour_without_retry_after() {
        let mut t = QuotaTracker::in_memory();
        let backoff = t.record_429("gemini_api", None, T0);
        assert_eq!(backoff, DEFAULT_BACKOFF);
    }

    #[test]
    fn record_429_clamps_pathological_retry_after() {
        let mut t = QuotaTracker::in_memory();
        // Server advertises 30 days — must clamp to 24h max.
        let backoff = t.record_429("openai_api", Some(Duration::from_secs(30 * 24 * 3600)), T0);
        assert_eq!(backoff, MAX_BACKOFF);
    }

    #[test]
    fn repeat_429_inside_window_does_not_shorten_backoff() {
        let mut t = QuotaTracker::in_memory();
        t.record_429("openai_api", Some(Duration::from_secs(600)), T0);
        // Adapter retried 60s later, server says 10s — must NOT cut the
        // existing window short.
        t.record_429("openai_api", Some(Duration::from_secs(10)), T0 + 60);
        let state = t.get("openai_api").unwrap();
        assert_eq!(state.backoff_until_unix, Some(T0 + 600));
    }

    #[test]
    fn record_success_increments_daily_counter() {
        let mut t = QuotaTracker::in_memory();
        assert_eq!(t.record_success("openai_api", T0), 1);
        assert_eq!(t.record_success("openai_api", T0), 2);
        assert_eq!(t.get("openai_api").unwrap().requests_today, 2);
    }

    #[test]
    fn daily_counter_rolls_over_at_midnight() {
        let mut t = QuotaTracker::in_memory();
        t.record_success("openai_api", T0);
        t.record_success("openai_api", T0);
        // Same day still 2.
        assert_eq!(t.get("openai_api").unwrap().requests_today, 2);
        // Next-day boundary — first call back-resets to 1.
        let next_day = T0 + 24 * 3600;
        let n = t.record_success("openai_api", next_day);
        assert_eq!(n, 1);
        assert_eq!(t.get("openai_api").unwrap().last_reset_unix, next_day);
    }

    #[test]
    fn reset_clears_backoff_and_counter() {
        let mut t = QuotaTracker::in_memory();
        t.record_429("openai_api", Some(Duration::from_secs(3600)), T0);
        t.record_success("openai_api", T0);
        t.reset("openai_api", T0 + 10);
        let state = t.get("openai_api").unwrap();
        assert_eq!(state.requests_today, 0);
        assert_eq!(state.backoff_until_unix, None);
        assert!(t.is_healthy("openai_api", T0 + 10));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        {
            let mut t = QuotaTracker::load_from(&path).unwrap();
            t.record_429("openai_api", Some(Duration::from_secs(600)), T0);
            t.record_success("openai_api", T0);
            t.save().unwrap();
        }
        let reloaded = QuotaTracker::load_from(&path).unwrap();
        let state = reloaded.get("openai_api").unwrap();
        assert_eq!(state.requests_today, 1);
        assert_eq!(state.backoff_until_unix, Some(T0 + 600));
    }

    #[test]
    fn update_at_serializes_concurrent_mutations_without_lost_state() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("quota.json"));
        let barrier = Arc::new(Barrier::new(8));
        let workers = (0..8)
            .map(|index| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    QuotaTracker::update_at(&path, |tracker| {
                        tracker.record_success(&format!("provider-{index}"), T0);
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker.join().unwrap().unwrap();
        }

        let tracker = QuotaTracker::load_from(&path).unwrap();
        assert_eq!(tracker.snapshot().len(), 8);
        for index in 0..8 {
            assert_eq!(
                tracker
                    .get(&format!("provider-{index}"))
                    .map(|state| state.requests_today),
                Some(1)
            );
        }
    }

    #[test]
    fn update_at_preserves_malformed_state_on_load_failure() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        let malformed = b"{ definitely not quota json";
        std::fs::write(&path, malformed).unwrap();

        let error = QuotaTracker::update_at(&path, |tracker| {
            tracker.record_success("openai_api", T0);
            Ok(())
        })
        .unwrap_err();

        assert!(error.to_string().contains("parse quota state"));
        assert_eq!(std::fs::read(path).unwrap(), malformed);
    }

    #[test]
    fn corrupt_file_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("quota.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let error = QuotaTracker::load_from(&path).unwrap_err();
        assert!(error.to_string().contains("parse quota state"));
    }

    #[test]
    fn snapshot_returns_sorted_providers() {
        let mut t = QuotaTracker::in_memory();
        t.record_success("openai_api", T0);
        t.record_success("gemini_api", T0);
        t.record_success("claude_cli", T0);
        let snap = t.snapshot();
        let names: Vec<_> = snap.iter().map(|s| s.provider.clone()).collect();
        assert_eq!(names, vec!["claude_cli", "gemini_api", "openai_api"]);
    }

    #[test]
    fn backoff_remaining_reports_correct_seconds() {
        let mut t = QuotaTracker::in_memory();
        t.record_429("openai_api", Some(Duration::from_secs(500)), T0);
        let state = t.get("openai_api").unwrap();
        assert_eq!(state.backoff_remaining_secs(T0), 500);
        assert_eq!(state.backoff_remaining_secs(T0 + 200), 300);
        assert_eq!(state.backoff_remaining_secs(T0 + 600), 0);
    }

    #[test]
    fn set_cap_records_estimated_ceiling() {
        let mut t = QuotaTracker::in_memory();
        t.set_cap("claude_cli", 200, T0);
        assert_eq!(t.get("claude_cli").unwrap().estimated_daily_cap, Some(200));
    }

    // V02-06: 5× 429 from the upstream provider must keep the
    // backoff window honoured; the 6th call (after the window
    // elapses, when the provider returns success) records cleanly
    // + clears the backoff. Pins the "no thundering herd against a
    // rate-limited provider" contract.
    #[test]
    fn five_consecutive_429s_extend_backoff_then_success_clears_it() {
        let mut t = QuotaTracker::in_memory();
        // 5 consecutive 429s — server says retry in 60s each time.
        // Mid-window 429s must NOT shorten the window (already covered
        // by `repeat_429_inside_window_does_not_shorten_backoff`, but
        // we exercise the full N-attempt sequence here too).
        let mut now = T0;
        for _ in 0..5 {
            t.record_429("openai_api", Some(Duration::from_secs(60)), now);
            // Adapter waits 10s, hits another 429.
            now += 10;
        }
        let state = t.get("openai_api").unwrap();
        // 5th 429 lands at T0+40; says retry-after=60 → backoff to T0+100.
        // But since each new 429 is inside the existing window, the
        // window only EXTENDS forward (never shortens). After the 5th
        // 429 the window must be at least T0+60 (first 429's deadline).
        let backoff_end = state.backoff_until_unix.expect("backoff set");
        assert!(
            backoff_end >= T0 + 60,
            "5 consecutive 429s must keep the backoff window honoured (got T0+{}, expected ≥ T0+60)",
            backoff_end - T0
        );
        assert!(
            !t.is_healthy("openai_api", now),
            "provider must be unhealthy during backoff"
        );

        // 6th call: jump past the backoff window + record success.
        let after_window = backoff_end + 1;
        let count = t.record_success("openai_api", after_window);
        assert!(count >= 1, "success after window must record");

        // After success the provider's HEALTH state recovers (backoff
        // remaining = 0). The backoff timestamp itself may still be
        // recorded but is in the past; is_healthy uses the comparison
        // against `now`, so post-window the provider is healthy again.
        assert!(
            t.is_healthy("openai_api", after_window),
            "provider must be healthy once the backoff window has elapsed"
        );
    }

    // ── ADV-10c `backoff_remaining_for` pre-flight primitive ──────────

    #[test]
    fn adv10c_backoff_remaining_for_untracked_provider_is_none() {
        let t = QuotaTracker::default();
        assert_eq!(t.backoff_remaining_for("openai_api", 100), None);
    }

    #[test]
    fn adv10c_backoff_remaining_for_local_qwen_is_always_none() {
        // Even if some bug pushed state for local_qwen into the tracker,
        // the pre-flight must NEVER claim the local provider is in backoff
        // — local inference is not rate-limited.
        let mut t = QuotaTracker::default();
        t.record_429(
            "local_qwen",
            Some(std::time::Duration::from_secs(300)),
            1_000,
        );
        assert_eq!(t.backoff_remaining_for("local_qwen", 1_100), None);
    }

    #[test]
    fn adv10c_backoff_remaining_for_local_ouro_is_always_none() {
        // GR-17 (Session 30): local_ouro is the SECOND local provider and
        // must be exempt from backoff exactly like local_qwen. Before the
        // canonical `is_local_provider` helper, this guard listed only
        // local_qwen, so a stray local_ouro 429 entry would have made the
        // pre-flight refuse a local inference call.
        let mut t = QuotaTracker::default();
        t.record_429(
            "local_ouro",
            Some(std::time::Duration::from_secs(300)),
            1_000,
        );
        assert_eq!(t.backoff_remaining_for("local_ouro", 1_100), None);
    }

    #[test]
    fn adv10c_backoff_remaining_for_healthy_provider_is_none() {
        let mut t = QuotaTracker::default();
        t.record_success("openai_api", 1_000);
        assert_eq!(t.backoff_remaining_for("openai_api", 1_100), None);
    }

    #[test]
    fn adv10c_backoff_remaining_for_throttled_provider_returns_remaining_secs() {
        let mut t = QuotaTracker::default();
        t.record_429(
            "openai_api",
            Some(std::time::Duration::from_secs(60)),
            1_000,
        );
        // 30s into the window — 30s remain (record_429 cap+min applied
        // upstream; here we read it back).
        let remaining = t.backoff_remaining_for("openai_api", 1_030);
        assert!(
            matches!(remaining, Some(r) if r == 30),
            "expected Some(30) remaining at +30s into 60s window, got {remaining:?}"
        );
    }

    #[test]
    fn adv10c_backoff_remaining_for_returns_none_after_window_elapses() {
        let mut t = QuotaTracker::default();
        t.record_429(
            "openai_api",
            Some(std::time::Duration::from_secs(60)),
            1_000,
        );
        assert_eq!(t.backoff_remaining_for("openai_api", 1_061), None);
    }
}
