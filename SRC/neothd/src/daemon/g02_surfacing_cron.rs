//! Round-3 v0.4 G-02 cron — daily-tick daemon loop that scans
//! `idx_profile` for novel high-confidence claims + enqueues each
//! as a `ProactiveItem` for the G-01 drain → sidecar chain.
//!
//! Glue between:
//! - `profile::surfacing::find_novel_high_confidence_claims` —
//!   pure-fn finder.
//! - `profile::surfacing::build_g02_proactive_item` — render
//!   bilingual ProactiveItem.
//! - `proactive::ProactiveQueue::enqueue` — bounded queue + dedup.
//! - `daemon::proactive_dispatcher` — drain loop into JSONL sidecar.
//!
//! Daily cadence matches the novelty window default — running
//! more frequently is wasteful (same claims surface; dedup key
//! catches the re-enqueue but it's a load on the queue's load+save
//! cycle). Operators tune via
//! `freedom.yaml::profile.g02_cron_interval_secs` in the follow-on.

use std::path::PathBuf;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Daily cadence — 24h in seconds. Per-claim dedup means more
/// frequent ticks just re-process the same set; no harm but no
/// gain.
pub const G02_CRON_INTERVAL_SECS: u64 = 24 * 3600;

/// Per-tick cap on claims enqueued. Caps the operator-visible
/// notification storm if a fresh extraction pass lands many
/// high-confidence claims at once.
pub const G02_PER_TICK_CAP: usize = 5;

/// Default channel for G-02 ProactiveItems. Operators see them in
/// the JSONL sidecar regardless of channel; the channel field gets
/// honoured once channel adapters consume the sidecar.
pub const G02_DEFAULT_CHANNEL: &str = "cli";

/// One G-02 tick: find novel claims in views.db, render each as a
/// ProactiveItem, enqueue into proactive_queue.json. Returns the
/// number of newly-enqueued items (dedup may reject some).
/// Pure-fn (no async) for testability.
pub fn run_g02_surfacing_tick(home: &std::path::Path, now_unix: i64) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;
    use crate::profile::surfacing::{
        DEFAULT_HIGH_CONFIDENCE_THRESHOLD, DEFAULT_NOVELTY_WINDOW_SECS, build_g02_proactive_item,
        find_novel_high_confidence_claims,
    };

    let views_path = home.join("views.db");
    if !views_path.exists() {
        // Fresh install — no profile yet. Quiet no-op so the cron
        // doesn't spam the log during the wizard's first week.
        return Ok(0);
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let since_unix = now_unix.saturating_sub(DEFAULT_NOVELTY_WINDOW_SECS as i64);
    let claims = find_novel_high_confidence_claims(
        &conn,
        since_unix,
        DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
        G02_PER_TICK_CAP,
    )
    .map_err(|e| format!("find_novel_high_confidence_claims failed: {e}"))?;
    if claims.is_empty() {
        return Ok(0);
    }

    let queue_path = home.join("proactive_queue.json");
    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;
    let mut enqueued_count = 0usize;
    for claim in &claims {
        let item = build_g02_proactive_item(claim, G02_DEFAULT_CHANNEL, now_unix);
        if queue.enqueue(item) {
            enqueued_count += 1;
        }
    }
    queue
        .save_to(&queue_path)
        .map_err(|e| format!("queue save failed: {e}"))?;
    Ok(enqueued_count)
}

/// Spawn the daemon-side G-02 cron loop. Matches the doctor_cron /
/// reflection_cron / proactive_dispatcher pattern.
pub fn spawn_g02_surfacing_cron_loop(home: PathBuf, interval_secs: u64) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(60));
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            home = %home.display(),
            "G-02 surfacing cron loop spawned"
        );
        // GOLD-ADAPT-ODY-07b — register this daemon-lifetime loop as a background
        // job so `neoth jobs list` + the ODY-07 bg_monitor see it as Running. No
        // `.exit` marker is ever written (the loop runs for the daemon's lifetime),
        // which is the accurate status. No-op before `init_global_registry` (chat).
        if let Some(reg) = crate::daemon::bg_jobs::global_registry() {
            let ts = crate::time::now_unix_secs();
            reg.register(
                crate::daemon::bg_jobs::BgJobId::new("g02-surfacing-cron", ts),
                "G-02 profile-claim surfacing loop",
                ts,
                None,
            )
            .await;
        }
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now_unix = chrono::Utc::now().timestamp();
            match run_g02_surfacing_tick(&home, now_unix) {
                Ok(0) => tracing::debug!("G-02 surfacing tick: no novel claims"),
                Ok(n) => info!(
                    enqueued = n,
                    "G-02 surfacing tick: {n} novel claim(s) enqueued for drain",
                ),
                Err(e) => warn!(error = %e, "G-02 surfacing tick failed; will retry next interval"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn g02_tick_no_views_db_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let n = run_g02_surfacing_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn g02_tick_empty_profile_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let views_path = tmp.path().join("views.db");
        let _conn = crate::memory::store::open(&views_path).unwrap();
        let n = run_g02_surfacing_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn g02_constants_canonical() {
        assert_eq!(G02_CRON_INTERVAL_SECS, 24 * 3600);
        assert_eq!(G02_PER_TICK_CAP, 5);
        assert_eq!(G02_DEFAULT_CHANNEL, "cli");
    }
}
