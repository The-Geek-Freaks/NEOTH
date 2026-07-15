//! GOLD-ADAPT-ODY-26 — session auto-sort cron.
//!
//! Re-implements the spirit of `odysseus/session_actions.py`'s session
//! grouping concept entirely from scratch (AGPL upstream was NOT read).
//! The spec is the tracker item description only.
//!
//! ## Pipeline (one pass)
//!
//! 1. **Load** all [`HindsightCard`]s via [`list_cards`].
//! 2. **Prune** unambiguous throwaway sessions (see `is_throwaway`).
//! 3. **Group** remaining sessions by calling an LLM with a prompt that
//!    takes the list of titles/summaries and returns JSON folder assignments.
//! 4. **Persist** folder assignment by tagging the card's `top_topics`
//!    field with a `"folder:<name>"` prefix entry (a synthetic topic slot
//!    that existing recall and display surfaces ignore unless they know to
//!    look for the prefix — it does not collide with organic topic tokens
//!    because natural `score_topics` output never starts with "folder:").
//!
//! ## Pruning predicate vs. spec divergence
//!
//! The tracker spec says "≤4-message or incognito sessions" should be pruned.
//! **`HindsightCard` carries neither an `incognito` flag nor a raw message
//! count** — only `turn_count` (operator+agent combined), `operator_turn_count`,
//! `agent_turn_count`, `one_line_summary`, and `top_topics`.
//!
//! **Decision**: prune conservatively on card-derivable signals only:
//! - `operator_turn_count <= 2` (≤2 operator turns ≈ ≤4 messages; if the
//!   operator said nothing or just one thing, the session had no real content)
//! - AND `top_topics.is_empty()` (no topics extracted = deterministic pass
//!   found nothing worth keeping)
//! - AND `one_line_summary` does not contain a colon after "on" (i.e. the
//!   summary is the degenerate form, e.g. "2 turns over 0 min on no clear topic")
//!
//! This is strictly more conservative than the ≤4-message threshold: it only
//! deletes cards where ALL three signals agree the session was empty. This
//! avoids false positives. A `dry_run` flag makes the prune a no-op delete.
//!
//! **No WAL scan.** The incognito case is undetectable from the card alone
//! (the WAL session-open frame is not read into the card). Incognito pruning
//! must be wired separately at card-write time if wanted.
//!
//! ## Folder tag format
//!
//! `"folder:<name>"` where `<name>` is the LLM-assigned folder label,
//! lowercase, spaces replaced with `-`. Example: `"folder:rust-debugging"`.
//! The tag is stored as the FIRST element of `top_topics` so recall surfaces
//! encounter it first. If a prior pass already set a folder tag the existing
//! one is replaced (idempotent re-grouping).
//!
//! ## Gating
//!
//! Controlled by `freedom.yaml::session_sort_cron.enabled` (default OFF,
//! same pattern as `checkin_cron`). Provider is required; if not wired the
//! spawn returns `None`. Default tick interval: 24h.

use std::path::Path;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::memory::hindsight::{HindsightCard, list_cards, save_card};
use crate::providers::{Provider, Request};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Summary returned by one sort pass — useful for tests and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortReport {
    pub cards_loaded: usize,
    pub cards_pruned: usize,
    pub cards_grouped: usize,
    pub folders_assigned: usize,
    /// Cards that the LLM grouped but whose card save failed.
    pub save_errors: usize,
    pub dry_run: bool,
}

/// A folder and the session IDs that belong to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub name: String,
    pub session_ids: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pruning predicate
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when the card is an unambiguous throwaway session.
///
/// Conservative: all three conditions must hold simultaneously.
/// See module doc for rationale + spec divergence.
pub fn is_throwaway(card: &HindsightCard) -> bool {
    // A folder tag means a prior sort pass already retained this card — it is
    // never throwaway regardless of the other signals.
    if card.top_topics.iter().any(|t| t.starts_with("folder:")) {
        return false; // prior pass retained it
    }

    // ① Very few operator turns (≤2 = effectively empty conversation)
    let thin = card.operator_turn_count <= 2;
    // ② No organic topics extracted at all (folder: tags already excluded above)
    let no_topics = card.top_topics.is_empty();
    // ③ Summary is the degenerate "no clear topic" shape
    let degenerate_summary = card.one_line_summary.contains("no clear topic");

    thin && no_topics && degenerate_summary
}

// ─────────────────────────────────────────────────────────────────────────────
// Grouping
// ─────────────────────────────────────────────────────────────────────────────

/// Pure function: call LLM with a list of session title/summary strings, parse
/// JSON back into `Vec<Folder>`.
///
/// On invalid JSON → returns `Ok(vec![])` (no grouping this pass) and logs
/// a warning.
/// On provider error → propagates `Err`.
pub async fn group_titles(
    cards: &[HindsightCard],
    provider: &dyn Provider,
) -> anyhow::Result<Vec<Folder>> {
    if cards.is_empty() {
        return Ok(vec![]);
    }

    // Build a numbered list: "<n>. [session_id] <display_name or one_line_summary>"
    let items: Vec<String> = cards
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let title = c.display_name.as_deref().unwrap_or(&c.one_line_summary);
            // Include top non-folder topics as context
            let topics: Vec<&str> = c
                .top_topics
                .iter()
                .filter(|t| !t.starts_with("folder:"))
                .map(|t| t.as_str())
                .take(3)
                .collect();
            if topics.is_empty() {
                format!("{}. [{}] {}", i + 1, c.session_id, title)
            } else {
                format!(
                    "{}. [{}] {} (topics: {})",
                    i + 1,
                    c.session_id,
                    title,
                    topics.join(", ")
                )
            }
        })
        .collect();

    let session_list = items.join("\n");

    let system = "You are a session organizer. Given a list of AI assistant session \
        summaries, group them into meaningful topic folders. \
        Return ONLY a valid JSON array. Each element must have: \
        \"folder\": string (short kebab-case name, max 32 chars), \
        \"session_ids\": array of session ID strings from the input. \
        Rules: every session must appear in exactly one folder. \
        3-8 folders total. Use concrete topic labels (e.g. \"rust-debugging\", \
        \"project-planning\", \"code-review\"). No markdown, no explanation. \
        Example: [{\"folder\":\"rust-debugging\",\"session_ids\":[\"abc123\"]}]";

    let prompt = format!(
        "Group these sessions into topic folders:\n\n{session_list}\n\n\
         Return JSON only."
    );

    let req = Request {
        prompt,
        system: Some(system.to_string()),
        ..Default::default()
    };

    let completion = provider.complete(req).await?;
    let raw = completion.text.trim();

    // Strip markdown code fence if present
    let json_str = raw
        .strip_prefix("```json")
        .or_else(|| raw.strip_prefix("```"))
        .and_then(|s| s.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(raw);

    // Parse defensively — invalid JSON → no grouping this pass
    let parsed: Vec<serde_json::Value> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                error = %e,
                raw = %&raw[..raw.len().min(200)],
                "session_sort_cron: LLM returned invalid JSON — skipping grouping this pass"
            );
            return Ok(vec![]);
        }
    };

    let mut folders: Vec<Folder> = Vec::new();
    for item in &parsed {
        let name = match item.get("folder").and_then(|v| v.as_str()) {
            Some(n) => n.to_lowercase().replace(' ', "-"),
            None => {
                warn!("session_sort_cron: folder entry missing 'folder' key — skipping entry");
                continue;
            }
        };
        let session_ids: Vec<String> = match item.get("session_ids").and_then(|v| v.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            None => {
                warn!(folder = %name, "session_sort_cron: missing 'session_ids' — skipping folder");
                continue;
            }
        };
        if !session_ids.is_empty() {
            folders.push(Folder { name, session_ids });
        }
    }

    Ok(folders)
}

// ─────────────────────────────────────────────────────────────────────────────
// Folder tag persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Apply folder assignment to a card's `top_topics` in-place and save it.
///
/// Replaces any existing `"folder:…"` prefix entry (idempotent). The tag is
/// inserted as the first element so display surfaces encounter it first.
fn apply_folder_tag(card: &mut HindsightCard, folder_name: &str) {
    // Sanitize: lowercase, spaces → dashes, strip non-alphanum-dash
    let sanitized: String = folder_name
        .to_lowercase()
        .chars()
        .map(|c| if c == ' ' { '-' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .take(48) // reasonable cap
        .collect();
    let tag = format!("folder:{sanitized}");

    // Remove any prior folder tag
    card.top_topics.retain(|t| !t.starts_with("folder:"));
    // Insert at front
    card.top_topics.insert(0, tag);
}

// ─────────────────────────────────────────────────────────────────────────────
// Core pass (testable, pure-ish)
// ─────────────────────────────────────────────────────────────────────────────

/// One full sort pass. `dry_run = true` → prune/save calls are skipped.
///
/// This is the testable heart; `spawn_session_sort_cron` just calls it on
/// a ticker.
pub async fn run_session_sort_pass(
    home: &Path,
    provider: &dyn Provider,
    dry_run: bool,
) -> anyhow::Result<SortReport> {
    // ── 1. Load ───────────────────────────────────────────────────────────
    let all_cards = list_cards(home);
    let cards_loaded = all_cards.len();

    if cards_loaded == 0 {
        debug!("session_sort_cron: no cards found — nothing to do");
        return Ok(SortReport {
            cards_loaded: 0,
            cards_pruned: 0,
            cards_grouped: 0,
            folders_assigned: 0,
            save_errors: 0,
            dry_run,
        });
    }

    // ── 2. Prune ──────────────────────────────────────────────────────────
    let mut cards_pruned = 0usize;
    let mut survivors: Vec<HindsightCard> = Vec::with_capacity(all_cards.len());

    for card in all_cards {
        if is_throwaway(&card) {
            if dry_run {
                debug!(session_id = %card.session_id, "session_sort_cron [dry_run]: would prune");
            } else {
                let path = crate::memory::hindsight::card_path(home, &card.session_id);
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(
                        session_id = %card.session_id,
                        error = %e,
                        "session_sort_cron: prune failed — keeping card"
                    );
                    survivors.push(card);
                    continue;
                }
                debug!(session_id = %card.session_id, "session_sort_cron: pruned throwaway");
            }
            cards_pruned += 1;
        } else {
            survivors.push(card);
        }
    }

    let cards_grouped = survivors.len();

    // ── 3. Group ──────────────────────────────────────────────────────────
    let folders = match group_titles(&survivors, provider).await {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "session_sort_cron: group_titles provider call failed — skipping grouping");
            return Ok(SortReport {
                cards_loaded,
                cards_pruned,
                cards_grouped,
                folders_assigned: 0,
                save_errors: 0,
                dry_run,
            });
        }
    };

    let folders_assigned = folders.len();

    // ── 4. Persist folder tags ────────────────────────────────────────────
    let mut save_errors = 0usize;

    if !dry_run {
        // Build session_id → folder_name map (first-wins: if the LLM puts the
        // same session_id in two folders the first folder assignment is kept and
        // a warning is emitted so the duplicate can be investigated).
        let mut id_to_folder: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for folder in &folders {
            for sid in &folder.session_ids {
                use std::collections::hash_map::Entry;
                match id_to_folder.entry(sid.clone()) {
                    Entry::Vacant(e) => {
                        e.insert(folder.name.clone());
                    }
                    Entry::Occupied(existing) => {
                        warn!(
                            session_id = %sid,
                            kept_folder = %existing.get(),
                            dropped_folder = %folder.name,
                            "session_sort_cron: LLM assigned session_id to multiple folders \
                             — keeping first assignment, dropping duplicate"
                        );
                    }
                }
            }
        }

        for mut card in survivors {
            if let Some(folder_name) = id_to_folder.get(&card.session_id) {
                apply_folder_tag(&mut card, folder_name);
                if let Err(e) = save_card(home, &card) {
                    warn!(
                        session_id = %card.session_id,
                        error = %e,
                        "session_sort_cron: failed to save card after tagging"
                    );
                    save_errors += 1;
                }
            }
        }
    } else {
        for folder in &folders {
            debug!(
                folder = %folder.name,
                sessions = ?folder.session_ids,
                "session_sort_cron [dry_run]: would tag"
            );
        }
    }

    Ok(SortReport {
        cards_loaded,
        cards_pruned,
        cards_grouped,
        folders_assigned,
        save_errors,
        dry_run,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI rendering helper
// ─────────────────────────────────────────────────────────────────────────────

/// Render cards grouped by their `"folder:…"` tag into a text tree.
///
/// Cards with no folder tag appear under `(ungrouped)`.
/// Called by `neoth sessions --folders` (the CLI shell that wires this is
/// separate; this fn is the render contract).
///
/// ```text
/// Folders:
/// ├── rust-debugging  (3 sessions)
/// │   ├── [2026-07-01] Borrow checker lifetime issue
/// │   └── [2026-06-28] Unsafe block audit
/// └── (ungrouped)  (1 session)
///     └── [2026-06-25] 2 turns over 0 min on config
/// ```
pub fn folders_view(cards: &[HindsightCard]) -> String {
    use std::collections::BTreeMap;

    // Group cards by folder name (BTreeMap for stable alpha order)
    let mut by_folder: BTreeMap<String, Vec<&HindsightCard>> = BTreeMap::new();

    for card in cards {
        let folder_tag = card
            .top_topics
            .iter()
            .find(|t| t.starts_with("folder:"))
            .and_then(|t| t.strip_prefix("folder:"))
            .map(str::to_owned)
            .unwrap_or_else(|| "(ungrouped)".to_string());
        by_folder.entry(folder_tag).or_default().push(card);
    }

    if by_folder.is_empty() {
        return "No sessions found.\n".to_string();
    }

    let mut out = String::from("Folders:\n");
    let folder_count = by_folder.len();

    for (idx, (folder, folder_cards)) in by_folder.iter().enumerate() {
        let is_last_folder = idx + 1 == folder_count;
        let branch = if is_last_folder {
            "└──"
        } else {
            "├──"
        };
        let child_prefix = if is_last_folder { "    " } else { "│   " };

        out.push_str(&format!(
            "{branch} {folder}  ({} session{})\n",
            folder_cards.len(),
            if folder_cards.len() == 1 { "" } else { "s" }
        ));

        for (ci, card) in folder_cards.iter().enumerate() {
            let is_last_card = ci + 1 == folder_cards.len();
            let card_branch = if is_last_card {
                "└──"
            } else {
                "├──"
            };
            let title = card
                .display_name
                .as_deref()
                .unwrap_or(&card.one_line_summary);
            // Format date from ended_at_unix
            let date = format_unix_date(card.ended_at_unix);
            out.push_str(&format!("{child_prefix}{card_branch} [{date}] {title}\n"));
        }
    }

    out
}

/// Format unix timestamp as `YYYY-MM-DD` (UTC, no external dep).
fn format_unix_date(unix_secs: i64) -> String {
    // Days since epoch
    let secs = unix_secs.max(0) as u64;
    let days = secs / 86_400;
    // Gregorian calendar computation (no chrono dep required)
    // Source algorithm: https://howardhinnant.github.io/date_algorithms.html
    // civil_from_days
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Spawn wrapper (mirrors checkin_cron pattern in serve_tasks.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the session-sort cron. Returns `None` when disabled or provider
/// unavailable (logs reason). Gated by `freedom.yaml::session_sort_cron.enabled`.
///
/// **Caller (serve_tasks)** snippet:
/// ```rust,ignore
/// let session_sort_handle = crate::daemon::session_sort_cron::spawn_session_sort_cron(
///     config,
///     reload_controller,
///     writer,
/// ).await;
/// ```
pub async fn spawn_session_sort_cron(
    config: &crate::config::FreedomConfig,
    reload_controller: &Arc<crate::config::reload::ReloadController>,
    home: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.session_sort_cron.enabled {
        return None;
    }

    let provider = match crate::providers::from_config(config).await {
        Ok(p) => Arc::new(
            crate::providers::cost_authorization::AuthorizedProvider::from_box(
                p,
                crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed_reload(
                    Arc::clone(reload_controller),
                    Some(writer.clone()),
                ),
                config.provider_model.clone(),
                "session_sort_cron",
            ),
        ),
        Err(e) => {
            warn!(
                error = %e,
                "session_sort_cron: provider build failed — cron disabled for this session"
            );
            return None;
        }
    };

    let ctrl = Arc::clone(reload_controller);
    let home = home.to_path_buf();
    let boot_cfg = config.session_sort_cron;

    info!(
        interval_secs = boot_cfg.interval_secs,
        dry_run = boot_cfg.dry_run,
        "session_sort_cron spawned (GOLD-ADAPT-ODY-26)"
    );

    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Burn the immediate tick — first boot has nothing new relative to
        // prior pass (mirrors arxiv_skill_scan_cron).
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().session_sort_cron;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }
            match run_session_sort_pass(&home, provider.as_ref(), live_cfg.dry_run).await {
                Ok(report) => {
                    info!(
                        loaded = report.cards_loaded,
                        pruned = report.cards_pruned,
                        grouped = report.cards_grouped,
                        folders = report.folders_assigned,
                        save_errors = report.save_errors,
                        dry_run = report.dry_run,
                        "session_sort_cron: pass complete"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "session_sort_cron: pass failed (will retry next tick)");
                }
            }
        }
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::hindsight::HindsightCard;
    use crate::providers::{Completion, Provider, Request};
    use async_trait::async_trait;
    use tempfile::tempdir;

    // ── Mock provider ──────────────────────────────────────────────────────

    struct MockProvider {
        /// Fixed JSON string to return
        response: String,
    }

    impl MockProvider {
        fn new(response: impl Into<String>) -> Self {
            Self {
                response: response.into(),
            }
        }
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                text: self.response.clone(),
                identity: Default::default(),
                model: "mock".to_string(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
        fn name(&self) -> &'static str {
            "mock"
        }
    }

    // ── Card builder helper ────────────────────────────────────────────────

    fn make_card(
        session_id: &str,
        operator_turns: usize,
        topics: Vec<&str>,
        summary: &str,
    ) -> HindsightCard {
        HindsightCard {
            session_id: session_id.to_string(),
            started_at_unix: 1_700_000_000,
            ended_at_unix: 1_700_003_600,
            turn_count: operator_turns * 2,
            operator_turn_count: operator_turns,
            agent_turn_count: operator_turns,
            top_topics: topics.into_iter().map(str::to_owned).collect(),
            opening_utterance: String::new(),
            closing_utterance: String::new(),
            one_line_summary: summary.to_string(),
            display_name: None,
        }
    }

    // ── Pruning predicate tests ────────────────────────────────────────────

    #[test]
    fn throwaway_when_all_three_signals_agree() {
        let card = make_card("s1", 1, vec![], "1 turns over 0 min on no clear topic");
        assert!(is_throwaway(&card));
    }

    #[test]
    fn not_throwaway_when_has_real_topics() {
        let card = make_card(
            "s2",
            1,
            vec!["rust", "lifetime"],
            "1 turns over 2 min on rust",
        );
        assert!(!is_throwaway(&card));
    }

    #[test]
    fn not_throwaway_when_enough_operator_turns() {
        let card = make_card("s3", 5, vec![], "5 turns over 3 min on no clear topic");
        // operator_turn_count=5 > 2 → not throwaway even with no topics
        assert!(!is_throwaway(&card));
    }

    #[test]
    fn not_throwaway_when_summary_has_real_topics_phrase() {
        let card = make_card("s4", 2, vec![], "4 turns over 1 min on rust, async");
        // summary does NOT contain "no clear topic"
        assert!(!is_throwaway(&card));
    }

    #[test]
    fn not_throwaway_when_only_folder_tag_present() {
        // DANGEROUS shape: all three throwaway signals agree (operator_turns≤2,
        // degenerate summary, no organic topics) — but a folder: tag is present,
        // meaning a prior sort pass retained this card. Must never be throwaway.
        let card = make_card(
            "s5",
            1,                                      // ≤2 operator turns — would pass signal ①
            vec!["folder:misc"], // only a folder tag, no organic topics — would pass signal ②
            "1 turns over 0 min on no clear topic", // degenerate — would pass signal ③
        );
        assert!(
            !is_throwaway(&card),
            "folder-tagged card must never be throwaway"
        );
    }

    #[test]
    fn dry_run_does_not_delete_files() {
        let dir = tempdir().unwrap();
        let card = make_card("dry1", 1, vec![], "1 turns over 0 min on no clear topic");
        save_card(dir.path(), &card).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = MockProvider::new("[]");
        let report = rt
            .block_on(run_session_sort_pass(dir.path(), &provider, true))
            .unwrap();

        assert_eq!(report.cards_pruned, 1);
        assert!(report.dry_run);
        // File must still exist
        let path = crate::memory::hindsight::card_path(dir.path(), "dry1");
        assert!(path.exists(), "dry_run must not delete files");
    }

    // ── group_titles tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn group_titles_valid_json_returns_folders() {
        let cards = vec![
            make_card("abc", 3, vec!["rust"], "3 turns over 2 min on rust"),
            make_card("def", 4, vec!["async"], "4 turns over 3 min on async"),
        ];
        let json = r#"[{"folder":"rust-work","session_ids":["abc"]},{"folder":"async-design","session_ids":["def"]}]"#;
        let provider = MockProvider::new(json);
        let folders = group_titles(&cards, &provider).await.unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].name, "rust-work");
        assert_eq!(folders[0].session_ids, vec!["abc"]);
        assert_eq!(folders[1].name, "async-design");
    }

    #[tokio::test]
    async fn group_titles_garbage_json_returns_empty() {
        let cards = vec![make_card(
            "x",
            3,
            vec!["rust"],
            "3 turns over 1 min on rust",
        )];
        let provider = MockProvider::new("this is not json at all {{{");
        let folders = group_titles(&cards, &provider).await.unwrap();
        assert!(
            folders.is_empty(),
            "invalid JSON must produce empty folder list"
        );
    }

    #[tokio::test]
    async fn group_titles_markdown_fenced_json_is_parsed() {
        let cards = vec![make_card(
            "y",
            3,
            vec!["memory"],
            "3 turns over 2 min on memory",
        )];
        let json = "```json\n[{\"folder\":\"memory-work\",\"session_ids\":[\"y\"]}]\n```";
        let provider = MockProvider::new(json);
        let folders = group_titles(&cards, &provider).await.unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].name, "memory-work");
    }

    #[tokio::test]
    async fn group_titles_empty_cards_returns_empty() {
        let provider = MockProvider::new("[]");
        let folders = group_titles(&[], &provider).await.unwrap();
        assert!(folders.is_empty());
    }

    // ── duplicate session_id across folders ───────────────────────────────────

    #[tokio::test]
    async fn group_titles_duplicate_session_id_first_folder_wins() {
        // LLM returns "dup-session" in both "folder-a" and "folder-b".
        // The persist layer must keep folder-a (first occurrence) and drop folder-b.
        // We drive this through run_session_sort_pass (dry_run=false) so the
        // id_to_folder map is actually exercised.
        let dir = tempdir().unwrap();
        // Create a card for the duplicated session_id
        let card = make_card("dup-session", 5, vec!["rust"], "5 turns over 3 min on rust");
        save_card(dir.path(), &card).unwrap();

        let json = r#"[
            {"folder":"folder-a","session_ids":["dup-session"]},
            {"folder":"folder-b","session_ids":["dup-session"]}
        ]"#;
        let provider = MockProvider::new(json);
        let report = run_session_sort_pass(dir.path(), &provider, false)
            .await
            .unwrap();

        // Report is consistent: one folder assignment triggered (folder-a wins)
        assert_eq!(report.cards_grouped, 1, "one surviving card");
        assert_eq!(report.save_errors, 0);

        // Reload card from disk and verify the folder tag is folder-a, not folder-b
        let saved = crate::memory::hindsight::list_cards(dir.path());
        assert_eq!(saved.len(), 1);
        let folder_tag = saved[0]
            .top_topics
            .iter()
            .find(|t| t.starts_with("folder:"))
            .map(String::as_str);
        assert_eq!(
            folder_tag,
            Some("folder:folder-a"),
            "first folder assignment must win; got {:?}",
            folder_tag
        );
    }

    // ── folder tag persistence ─────────────────────────────────────────────

    #[test]
    fn apply_folder_tag_inserts_at_front() {
        let mut card = make_card("t1", 3, vec!["rust", "async"], "...");
        apply_folder_tag(&mut card, "rust-work");
        assert_eq!(card.top_topics[0], "folder:rust-work");
        assert!(card.top_topics.contains(&"rust".to_string()));
    }

    #[test]
    fn apply_folder_tag_replaces_prior_tag() {
        let mut card = make_card("t2", 3, vec!["folder:old-name", "rust"], "...");
        apply_folder_tag(&mut card, "new-name");
        let folder_tags: Vec<_> = card
            .top_topics
            .iter()
            .filter(|t| t.starts_with("folder:"))
            .collect();
        assert_eq!(folder_tags.len(), 1, "only one folder tag allowed");
        assert_eq!(folder_tags[0], "folder:new-name");
    }

    #[test]
    fn apply_folder_tag_sanitizes_spaces() {
        let mut card = make_card("t3", 3, vec![], "...");
        apply_folder_tag(&mut card, "Rust Debugging");
        assert_eq!(card.top_topics[0], "folder:rust-debugging");
    }

    // ── folders_view rendering ─────────────────────────────────────────────

    #[test]
    fn folders_view_renders_grouped_cards() {
        let mut card1 = make_card("s1", 3, vec![], "session one");
        card1.display_name = Some("Session One".to_string());
        apply_folder_tag(&mut card1, "rust-work");

        let mut card2 = make_card("s2", 3, vec![], "session two");
        apply_folder_tag(&mut card2, "planning");

        let view = folders_view(&[card1, card2]);
        assert!(view.contains("rust-work"), "should contain folder name");
        assert!(view.contains("planning"));
        assert!(view.contains("Session One"), "should contain display_name");
    }

    #[test]
    fn folders_view_ungrouped_fallback() {
        let card = make_card("u1", 3, vec!["rust"], "3 turns over 2 min on rust");
        let view = folders_view(&[card]);
        assert!(view.contains("(ungrouped)"));
    }

    #[test]
    fn folders_view_empty_cards() {
        let view = folders_view(&[]);
        assert_eq!(view, "No sessions found.\n");
    }

    // ── format_unix_date ───────────────────────────────────────────────────

    #[test]
    fn format_unix_date_known_value() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(format_unix_date(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn format_unix_date_zero() {
        // Unix epoch = 1970-01-01
        assert_eq!(format_unix_date(0), "1970-01-01");
    }
}
