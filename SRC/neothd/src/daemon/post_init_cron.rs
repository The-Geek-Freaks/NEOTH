//! GOLD-FEAT-11 — one-shot post-init healthcheck proactive item producer.
//!
//! Runs ONCE at serve startup (after the WAL is live) to check whether the
//! operator completed onboarding. If the `.initialized` marker exists but
//! readiness gaps are detected, it enqueues a single `ProactiveItem` into
//! `~/.neoth/proactive_queue.json` so the existing `spawn_proactive_dispatcher`
//! drain loop delivers it on its next tick.
//!
//! Design notes:
//! - **One-shot**, not a cron loop. Enqueued dedup_key carries the neothd
//!   binary version so a daemon upgrade re-fires the check.
//! - **No new WAL byte.** Queue enqueue is the only side-effect.
//! - **Best-effort.** Callers `tokio::spawn` this detached; errors are logged
//!   at warn level only.

use std::path::Path;

use tracing::warn;

use crate::proactive::ProactiveItem;

/// Run the post-init healthcheck once and, if gaps are found, enqueue a
/// `ProactiveItem` into `~/.neoth/proactive_queue.json`.
///
/// Called from `cli/serve.rs` via a detached `tokio::spawn` after
/// `spawn_proactive_dispatcher` is alive.
pub async fn run_post_init_check(home: &std::path::PathBuf) {
    if let Err(e) = run_post_init_check_inner(home).await {
        warn!(error = %e, "post_init_cron: check failed (best-effort, ignoring)");
    }
}

async fn run_post_init_check_inner(home: &Path) -> anyhow::Result<()> {
    use crate::proactive::ProactiveQueue;

    // Skip entirely if .initialized is absent — the wizard hasn't run yet.
    let marker = home.join(".initialized");
    if !marker.exists() {
        return Ok(());
    }

    // Evaluate readiness using the same logic as the doctor check.
    let gaps = collect_onboarding_gaps(home);
    if gaps.is_empty() {
        // All good — no nudge needed.
        return Ok(());
    }

    let version = env!("CARGO_PKG_VERSION");
    let dedup_key = format!("post_init_check:{version}");

    let body = format!(
        "Onboarding checklist — some setup steps are incomplete:\n{}\n\
         Run `neoth doctor --explain \"post-init readiness\"` for fix steps.",
        gaps.iter()
            .map(|g| format!("  • {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let item = ProactiveItem {
        priority: 80,
        dedup_key,
        channel: String::new(), // operator default channel
        source: "post_init_check".to_string(),
        body,
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    };

    let queue_path = home.join("proactive_queue.json");
    let mut queue = if queue_path.exists() {
        ProactiveQueue::load_from(&queue_path)
            .map_err(|e| anyhow::anyhow!("queue load: {e}"))?
    } else {
        ProactiveQueue::new()
    };

    // enqueue returns false when the dedup_key already exists — no-op on
    // re-runs within the same binary version.
    if queue.enqueue(item) {
        queue
            .save_to(&queue_path)
            .map_err(|e| anyhow::anyhow!("queue save: {e}"))?;
        tracing::info!("post_init_cron: enqueued onboarding checklist item ({} gap(s))", gaps.len());
    } else {
        tracing::debug!("post_init_cron: item already queued (dedup), skipping");
    }

    Ok(())
}

/// Collect human-readable gap descriptions. Same logic as the doctor check
/// in `cli/doctor/checks/onboarding.rs` so both surfaces stay in sync.
fn collect_onboarding_gaps(home: &Path) -> Vec<String> {
    let mut gaps = Vec::new();

    let freedom_path = home.join("freedom.yaml");
    let cfg = match crate::config::FreedomConfig::load_from_path(&freedom_path) {
        Ok(c) => c,
        Err(_) => {
            gaps.push("freedom.yaml missing or unreadable — run `neoth init`".to_string());
            return gaps;
        }
    };

    // Provider wired?
    let kind_str = serde_yaml::to_string(&cfg.provider_kind)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let creds_ok = home.join("credentials.yaml").exists();
    let has_provider = !kind_str.is_empty()
        && (creds_ok || kind_str.contains("local_qwen") || kind_str.contains("antigravity"));
    if !has_provider {
        gaps.push(
            "provider not wired — no credentials.yaml for the configured provider_kind".to_string(),
        );
    }

    // Channel token present?
    let has_channel = {
        let creds_path = home.join("credentials.yaml");
        if creds_path.exists() {
            match crate::config::credentials::Credentials::load_or_default(&creds_path) {
                Ok(c) => {
                    c.telegram_token.is_some()
                        || c.slack_bot_token.is_some()
                        || c.discord_bot_token.is_some()
                        || c.whatsapp_token.is_some()
                }
                Err(_) => false,
            }
        } else {
            false
        }
    };
    if !has_channel {
        gaps.push(
            "no channel token (Telegram/Slack/Discord/WhatsApp) — proactive delivery is silent"
                .to_string(),
        );
    }

    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn skips_when_no_initialized_marker() {
        let dir = tempdir().unwrap();
        // Should succeed (no-op) without creating a queue file.
        run_post_init_check(&dir.path().to_path_buf()).await;
        assert!(!dir.path().join("proactive_queue.json").exists());
    }

    #[tokio::test]
    async fn enqueues_when_not_ready() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        // No freedom.yaml → gaps detected
        run_post_init_check(&dir.path().to_path_buf()).await;
        let queue_path = dir.path().join("proactive_queue.json");
        assert!(
            queue_path.exists(),
            "queue should exist after enqueue"
        );
        let queue = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
        assert!(!queue.is_empty(), "should have one item");
        // Verify source tag
        // drain with a far-future now to get the item
        let mut q2 = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
        let items = q2.drain(i64::MAX, 10);
        assert!(!items.is_empty());
        assert_eq!(items[0].source, "post_init_check");
        assert!(items[0].dedup_key.starts_with("post_init_check:"));
    }

    #[tokio::test]
    async fn idempotent_on_second_call() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        run_post_init_check(&dir.path().to_path_buf()).await;
        run_post_init_check(&dir.path().to_path_buf()).await;
        let queue_path = dir.path().join("proactive_queue.json");
        let queue = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
        // dedup_key prevents double-enqueue
        assert_eq!(queue.len(), 1, "idempotent: only one item in queue");
    }

    #[tokio::test]
    async fn no_enqueue_when_fully_ready() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: test\nprovider_kind: openai_api\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abc\"\n",
        )
        .unwrap();
        run_post_init_check(&dir.path().to_path_buf()).await;
        // No gaps → no queue file created
        assert!(
            !dir.path().join("proactive_queue.json").exists(),
            "no item should be enqueued when fully ready"
        );
    }
}
