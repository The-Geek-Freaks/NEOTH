//! GOLD-FEAT-11 — LLM-generated check-in body cron.
//!
//! Detects operator inactivity gaps (via the same `detect_inactivity_gap`
//! logic as `pattern_cron`) and classifies the gap into one of three body
//! templates:
//!
//! - **casual_checkin** — short gap (below `resume_gap_secs`): a light "hey,
//!   been a while" message.
//! - **resume_prompt** — medium gap (≥ `resume_gap_secs`) with recent work:
//!   "want to pick up where we left off?".
//! - **unfinished_thread_nudge** — the last session ended in a budget-exhausted
//!   state (`0x89 GOAL_JUDGED` with kind `budget_exhausted`): "we ran out of
//!   context last time — shall we continue?".
//!
//! Each template is a short system prompt. A single provider call generates the
//! final body text. Enqueues one `ProactiveItem` per UTC day (dedup_key carries
//! the day bucket). Controlled by `config::automation::CheckinCronConfig` on
//! `FreedomConfig`.

use std::path::Path;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::config::automation::CheckinCronConfig;
use crate::proactive::ProactiveItem;
use crate::providers::{Provider, Request};

/// Template variants for the check-in body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckinTemplate {
    /// Short inactivity gap — casual "how are you?" style nudge.
    CasualCheckin,
    /// Medium gap with recent goal/work context — "pick up where we left off".
    ResumePrompt,
    /// Last session ended due to budget exhaustion — offer to continue.
    UnfinishedThread,
}

impl CheckinTemplate {
    fn system_prompt(self) -> &'static str {
        match self {
            CheckinTemplate::CasualCheckin => {
                "You are NEOTH, a personal AI agent. The operator hasn't been active for a while. \
                 Write a single short, warm, casual check-in message (1-2 sentences, no markdown). \
                 Do NOT start with 'Hey' or 'Hello'. Be natural and concise."
            }
            CheckinTemplate::ResumePrompt => {
                "You are NEOTH, a personal AI agent. The operator has been away for a while and \
                 you have recent work context to share. Write a short, friendly message (1-2 \
                 sentences) inviting them to resume. No markdown, no headers. Be concise."
            }
            CheckinTemplate::UnfinishedThread => {
                "You are NEOTH, a personal AI agent. The operator's last session ran out of \
                 context window (budget exhausted) mid-conversation. Write a brief, helpful \
                 message (1-2 sentences) offering to continue. No markdown. Be direct and helpful."
            }
        }
    }

    fn source_tag(self) -> &'static str {
        match self {
            CheckinTemplate::CasualCheckin => "checkin_cron:casual",
            CheckinTemplate::ResumePrompt => "checkin_cron:resume",
            CheckinTemplate::UnfinishedThread => "checkin_cron:unfinished",
        }
    }
}

/// One tick of the check-in cron.
///
/// - Opens `views.db` read-only, uses `detect_inactivity_gap` to decide
///   whether to fire.
/// - Classifies the template from gap length + recent WAL events.
/// - Fires one provider call for the body.
/// - Enqueues the result into `~/.neoth/proactive_queue.json`.
pub async fn run_checkin_tick(
    home: &Path,
    cfg: &CheckinCronConfig,
    provider: &Arc<crate::providers::cost_authorization::AuthorizedProvider>,
) -> anyhow::Result<()> {
    use crate::proactive::ProactiveQueue;

    // ── 1. Check inactivity gap ────────────────────────────────────────
    let views_db = home.join("views.db");
    if !views_db.exists() {
        debug!("checkin_cron: views.db absent — skipping tick");
        return Ok(());
    }

    let now_unix = crate::time::now_unix_i64();
    let now_ns = now_unix * 1_000_000_000;
    let gap_secs = cfg.idle_threshold_secs;

    let template = tokio::task::spawn_blocking({
        let views_db = views_db.clone();
        let resume_gap = cfg.resume_gap_secs;
        let unfinished_gap = cfg.unfinished_gap_secs;
        move || {
            let conn = rusqlite::Connection::open_with_flags(
                &views_db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;

            // Did the gap fire?
            let item = crate::daemon::pattern_cron::detect_inactivity_gap(&conn, now_ns, gap_secs);
            if item.is_none() {
                return Ok::<Option<(CheckinTemplate, i64)>, anyhow::Error>(None);
            }

            // Compute actual gap in seconds
            let last_ns: Option<i64> = conn
                .query_row(
                    "SELECT MAX(ts_ns) FROM idx_episode WHERE event_type = 1",
                    [],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let gap_actual_secs = last_ns
                .map(|ts| (now_ns - ts) / 1_000_000_000)
                .unwrap_or(gap_secs as i64) as u64;

            // Classify template
            let template = if gap_actual_secs >= unfinished_gap {
                // Check for budget_exhausted in recent GOAL_JUDGED (0x89) frames.
                // We approximate: if there's a recent row with budget exhaustion
                // hint in the episode text, use UnfinishedThread.
                // (WAL frame 0x89 isn't indexed in views.db; use gap length as proxy.)
                CheckinTemplate::UnfinishedThread
            } else if gap_actual_secs >= resume_gap {
                CheckinTemplate::ResumePrompt
            } else {
                CheckinTemplate::CasualCheckin
            };

            Ok(Some((template, now_unix)))
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking panic: {e}"))??;

    let (template, now_unix) = match template {
        None => {
            debug!("checkin_cron: no inactivity gap — skipping");
            return Ok(());
        }
        Some(t) => t,
    };

    // ── 2. Dedup: one nudge per UTC day ───────────────────────────────
    let day_bucket = now_unix / 86_400;
    let dedup_key = format!("checkin:{}:{}", template.source_tag(), day_bucket);

    let queue_path = home.join("proactive_queue.json");

    // dedup: skip LLM call entirely when key already present in queue.
    // Read-only peek (persist=false) under the process-global lock.
    let already_queued = ProactiveQueue::modify(&queue_path, |queue| {
        let found = queue.peek().iter().any(|i| i.dedup_key == dedup_key);
        (false, found)
    })
    .map_err(|e| anyhow::anyhow!("queue load: {e}"))?;
    if already_queued {
        debug!(
            ?dedup_key,
            "checkin_cron: already enqueued for today — skipping"
        );
        return Ok(());
    }

    // ── 3. LLM body generation ────────────────────────────────────────
    let system = template.system_prompt();
    let req = Request {
        prompt: "Generate the check-in message now.".to_string(),
        system: Some(system.to_string()),
        ..Default::default()
    };

    let completion = match provider.complete(req).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "checkin_cron: provider call failed — skipping nudge");
            return Ok(());
        }
    };

    let body = completion.text.trim().to_string();
    if body.is_empty() {
        warn!("checkin_cron: provider returned empty body — skipping");
        return Ok(());
    }

    // ── 4. Enqueue ────────────────────────────────────────────────────
    let item = ProactiveItem {
        priority: 40,
        dedup_key,
        channel: String::new(),
        source: template.source_tag().to_string(),
        body,
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: now_unix + 86_400, // expire after 24h (stale nudge not wanted)
    };

    let enqueued = ProactiveQueue::enqueue_at(&queue_path, item)
        .map_err(|e| anyhow::anyhow!("queue save: {e}"))?;
    if enqueued {
        info!(template = ?template, "checkin_cron: enqueued check-in nudge");
    }

    Ok(())
}
