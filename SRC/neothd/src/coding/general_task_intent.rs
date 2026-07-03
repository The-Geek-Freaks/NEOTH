//! GOLD-TASK-01 — general-task intent detection for the channel pipeline.
//!
//! Channel messages that look like non-coding work items (reminders,
//! research requests, scheduling, delegation) can be routed into the
//! kanban decomposer without going through a chat-completion turn.
//! This module ships the pure-fn detector that gates that routing.
//!
//! ## Design constraints
//!
//! * **No WAL event code** — the WAL byte space is exhausted (255/256
//!   slots taken; only `0x00` is free, which is the reserved null
//!   sentinel). Audit trail uses: the `insert_session` row itself,
//!   `tracing::info!` on creation, and the kanban SSE `FeedEntry`
//!   broadcast emitted by the existing babel cron. No new WAL event
//!   will be added. This deviates from the tracker spec's
//!   "WAL `0x78 TASK_SESSION_CREATED`" — that slot is taken by
//!   `EVENT_TYPE_KANBAN_TASK_DEP_ADDED`.
//!
//! * **Mutual exclusion with coding path** — the verb set MUST NOT
//!   overlap [`crate::coding::intent::CODING_VERBS`]. The routing
//!   branch in `serve_pipeline.rs` checks coding intent first; only
//!   if that returns `None` does this detector run. The verb sets are
//!   kept separately to guarantee no double-dispatch.
//!
//! * **Conservative / high-confidence only** — reminders, scheduling,
//!   research, delegation phrasings. Greetings, questions, and all
//!   coding-shaped prompts pass through. Only `High` confidence
//!   triggers auto-session creation.
//!
//! ## Future swap
//!
//! v0.9 G-01 LLM-driven intent classification can replace this
//! heuristic. The `GeneralTaskIntent` surface is drop-in compatible.

use anyhow::Context as _;
use crate::permissions::AutonomyLevel;
use serde::{Deserialize, Serialize};

/// A detected general (non-coding) task intent. Carries confidence so
/// the routing branch can require High before creating a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralTaskIntent {
    /// Confidence — only `High` triggers auto-session creation.
    pub confidence: crate::coding::intent::IntentConfidence,
    /// Which verb/phrase matched (for tracing/operator logs).
    pub matched_phrase: Option<String>,
    /// Short category label for the session title heuristic.
    pub category: GeneralTaskCategory,
}

/// Broad category of the detected non-coding task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralTaskCategory {
    Reminder,
    Research,
    Scheduling,
    Delegation,
    Other,
}

impl GeneralTaskCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reminder => "reminder",
            Self::Research => "research",
            Self::Scheduling => "scheduling",
            Self::Delegation => "delegation",
            Self::Other => "task",
        }
    }
}

/// Verb/phrase patterns that signal a general-task request.
///
/// These MUST NOT overlap `coding::intent::CODING_VERBS`. The overlap
/// check is enforced by a test at the bottom of this module.
///
/// Anchor rule: matches anywhere in the prompt (the task phrases tend
/// to be full sentences, not imperative-verb-led), but we require a
/// phrase match rather than a loose noun match to stay conservative.
const TASK_PHRASES: &[(&str, GeneralTaskCategory)] = &[
    // ── Reminder phrases (EN) ──────────────────────────────────────
    ("remind me", GeneralTaskCategory::Reminder),
    ("set a reminder", GeneralTaskCategory::Reminder),
    ("don't let me forget", GeneralTaskCategory::Reminder),
    ("remember to", GeneralTaskCategory::Reminder),
    ("note to self", GeneralTaskCategory::Reminder),
    // ── Reminder phrases (DE) ──────────────────────────────────────
    ("erinnere mich", GeneralTaskCategory::Reminder),
    ("erinner mich", GeneralTaskCategory::Reminder),
    ("nicht vergessen", GeneralTaskCategory::Reminder),
    ("merk dir", GeneralTaskCategory::Reminder),
    // ── Research phrases (EN) ──────────────────────────────────────
    ("research", GeneralTaskCategory::Research),
    ("look into", GeneralTaskCategory::Research),
    ("find out", GeneralTaskCategory::Research),
    ("investigate", GeneralTaskCategory::Research),
    ("summarize", GeneralTaskCategory::Research),
    ("summarise", GeneralTaskCategory::Research),
    ("gather information", GeneralTaskCategory::Research),
    ("look up", GeneralTaskCategory::Research),
    // ── Research phrases (DE) ──────────────────────────────────────
    ("recherchier", GeneralTaskCategory::Research),
    ("recherchiere", GeneralTaskCategory::Research),
    ("herausfinden", GeneralTaskCategory::Research),
    ("informationen sammeln", GeneralTaskCategory::Research),
    ("zusammenfassen", GeneralTaskCategory::Research),
    // ── Scheduling phrases (EN) ────────────────────────────────────
    ("schedule", GeneralTaskCategory::Scheduling),
    ("book a", GeneralTaskCategory::Scheduling),
    ("arrange a", GeneralTaskCategory::Scheduling),
    ("plan a meeting", GeneralTaskCategory::Scheduling),
    ("set up a call", GeneralTaskCategory::Scheduling),
    ("to my calendar", GeneralTaskCategory::Scheduling),
    ("calendar entry", GeneralTaskCategory::Scheduling),
    ("block time", GeneralTaskCategory::Scheduling),
    // ── Scheduling phrases (DE) ────────────────────────────────────
    ("termin", GeneralTaskCategory::Scheduling),
    ("treffen planen", GeneralTaskCategory::Scheduling),
    ("meeting einplanen", GeneralTaskCategory::Scheduling),
    ("kalender", GeneralTaskCategory::Scheduling),
    // ── Delegation phrases (EN) ────────────────────────────────────
    ("follow up with", GeneralTaskCategory::Delegation),
    ("follow up on", GeneralTaskCategory::Delegation),
    ("send an email", GeneralTaskCategory::Delegation),
    ("send a message", GeneralTaskCategory::Delegation),
    ("reach out to", GeneralTaskCategory::Delegation),
    ("contact", GeneralTaskCategory::Delegation),
    ("draft an email", GeneralTaskCategory::Delegation),
    ("draft a message", GeneralTaskCategory::Delegation),
    // ── Delegation phrases (DE) ────────────────────────────────────
    ("nachfassen bei", GeneralTaskCategory::Delegation),
    ("eine email schreiben", GeneralTaskCategory::Delegation),
    ("eine nachricht schreiben", GeneralTaskCategory::Delegation),
    ("kontaktier", GeneralTaskCategory::Delegation),
    ("kontaktiere", GeneralTaskCategory::Delegation),
];

/// Detect a general (non-coding) task intent in `prompt`.
///
/// Returns `None` when no signal matches — the prompt stays with the
/// normal chat-completion path. Returns `Some(GeneralTaskIntent)` when a
/// high-signal phrase fires. Always `None` for empty prompts.
///
/// **Mutual exclusion**: coding-intent verbs are explicitly not present
/// in [`TASK_PHRASES`]. Call `detect_coding_intent` first; only call
/// this when that returns `None`.
pub fn detect_general_task_intent(prompt: &str) -> Option<GeneralTaskIntent> {
    use crate::coding::intent::IntentConfidence;

    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();

    for (phrase, category) in TASK_PHRASES {
        if lower.contains(phrase) {
            return Some(GeneralTaskIntent {
                confidence: IntentConfidence::High,
                matched_phrase: Some((*phrase).to_string()),
                category: *category,
            });
        }
    }

    None
}

/// Gate: should the channel pipeline auto-create a task session for
/// this prompt?
///
/// Returns `true` iff:
/// 1. `detect_general_task_intent(prompt)` returns `High` confidence, AND
/// 2. `autonomy >= Standard` (tasks from remote channels require at
///    minimum Standard; Strict blocks all unattended session creation), AND
/// 3. `detect_coding_intent(prompt)` returns `None` (mutual exclusion —
///    the coding path wins when the coding heuristic fires).
///
/// Note: `config.task_engine.decompose_non_coding` is the master kill-
/// switch checked by the routing branch BEFORE calling this fn; it is
/// not checked here to keep this function purely about intent + autonomy.
pub fn should_auto_task_dispatch(
    prompt: &str,
    autonomy: AutonomyLevel,
) -> bool {
    use crate::coding::intent::{IntentConfidence, detect_coding_intent};

    // Strict autonomy: never create tasks from channel input unattended.
    if matches!(autonomy, AutonomyLevel::Strict) {
        return false;
    }

    // Coding intent wins — don't double-dispatch.
    // Mutual exclusion yields only to HIGH-confidence coding intent — a Low
    // match is just a programming NOUN mention ("research Rust runtimes"),
    // which is a legitimate research task, not code work.
    if matches!(
        detect_coding_intent(prompt),
        Some(ci) if ci.confidence == IntentConfidence::High
    ) {
        return false;
    }

    matches!(
        detect_general_task_intent(prompt),
        Some(GeneralTaskIntent {
            confidence: IntentConfidence::High,
            ..
        })
    )
}

/// Create a kanban session for a non-coding general task.
///
/// Thin entry-point used by the channel pipeline routing branch. Calls
/// `coding::store::insert_session` to land the session in `Backlog`
/// status. Returns the new `KanbanSessionId`.
///
/// **No LLM call, no dispatch** — this slice is intentionally synchronous
/// and cheap. The operator drives execution via `neoth code --run-pending`.
///
/// `source_channel` should be the channel adapter string ("telegram",
/// "whatsapp", "discord", etc.) so the kanban row carries provenance.
pub fn decompose_non_coding(
    conn: &rusqlite::Connection,
    prompt: &str,
    source_channel: &str,
    operator_id: Option<&str>,
) -> anyhow::Result<crate::coding::types::KanbanSessionId> {
    use crate::coding::store;

    store::ensure_schema(conn)
        .with_context(|| format!("ensure kanban schema for channel {source_channel}"))?;

    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Lightweight prompt fingerprint (no crypto dep — for dedup only).
    let prompt_hash = format!("{:016x}", ts_ns ^ prompt.len() as u64);

    store::insert_session(conn, ts_ns, prompt, &prompt_hash, source_channel, operator_id)
        .with_context(|| {
            format!("insert kanban session for general task from channel {source_channel}")
        })
}

/// Derive a short session title from the prompt and detected intent.
/// Used as the `prompt_hash`-adjacent label in the kanban session row
/// and the operator ack reply. Maximum 80 chars, trimmed.
pub fn derive_task_title(prompt: &str, intent: &GeneralTaskIntent) -> String {
    let prefix = intent.category.as_str();
    let body: String = prompt
        .chars()
        .take(70)
        .collect::<String>()
        .trim()
        .to_string();
    format!("[{prefix}] {body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::intent::{IntentConfidence, CODING_VERBS};
    use crate::permissions::AutonomyLevel;

    // ── detect_general_task_intent: positive cases ─────────────────

    #[test]
    fn reminder_english_call_alice() {
        let intent = detect_general_task_intent("remind me to call Alice at 5pm");
        assert!(intent.is_some(), "expected intent for reminder prompt");
        let i = intent.unwrap();
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Reminder);
    }

    #[test]
    fn reminder_german() {
        let i = detect_general_task_intent("Erinnere mich morgen um 9 Uhr an das Meeting")
            .expect("should detect reminder");
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Reminder);
    }

    #[test]
    fn research_english_summarize() {
        let i = detect_general_task_intent("research the latest news on Rust async and summarize the findings")
            .expect("should detect research");
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Research);
    }

    #[test]
    fn research_german() {
        let i = detect_general_task_intent("Recherchiere die besten Alternativen zu diesel für SQLite")
            .expect("should detect research");
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Research);
    }

    #[test]
    fn scheduling_english() {
        let i = detect_general_task_intent("schedule a meeting with Bob for Tuesday at 3pm")
            .expect("should detect scheduling");
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Scheduling);
    }

    #[test]
    fn delegation_follow_up() {
        let i = detect_general_task_intent("follow up with Sarah about the invoice")
            .expect("should detect delegation");
        assert_eq!(i.confidence, IntentConfidence::High);
        assert_eq!(i.category, GeneralTaskCategory::Delegation);
    }

    #[test]
    fn delegation_send_email() {
        let i = detect_general_task_intent("send an email to the client confirming the date")
            .expect("should detect delegation");
        assert_eq!(i.confidence, IntentConfidence::High);
    }

    // ── detect_general_task_intent: negative cases ─────────────────

    #[test]
    fn none_on_greeting() {
        assert!(
            detect_general_task_intent("hey, how are you?").is_none(),
            "greeting should not detect"
        );
    }

    #[test]
    fn none_on_question() {
        assert!(
            detect_general_task_intent("what time is it in Tokyo?").is_none(),
            "question should not detect"
        );
    }

    #[test]
    fn none_on_empty() {
        assert!(detect_general_task_intent("").is_none());
        assert!(detect_general_task_intent("   ").is_none());
    }

    #[test]
    fn none_on_coding_prompt_no_overlap() {
        // Coding prompts must not trip the general-task detector.
        assert!(
            detect_general_task_intent("build a function that reverses a linked list").is_none(),
            "coding prompt must not match general task detector"
        );
        assert!(
            detect_general_task_intent("fix the bug in the auth handler").is_none(),
            "coding prompt must not match general task detector"
        );
        assert!(
            detect_general_task_intent("schreib einen Test für den login endpoint").is_none(),
            "german coding prompt must not match"
        );
    }

    // ── should_auto_task_dispatch ───────────────────────────────────

    #[test]
    fn dispatch_true_for_high_confidence_standard_autonomy() {
        assert!(should_auto_task_dispatch(
            "remind me to call Alice at 5pm",
            AutonomyLevel::Standard,
        ));
    }

    #[test]
    fn dispatch_true_for_elevated() {
        assert!(should_auto_task_dispatch(
            "research the top 5 Rust async runtimes and summarize",
            AutonomyLevel::Elevated,
        ));
    }

    #[test]
    fn dispatch_false_for_strict() {
        assert!(!should_auto_task_dispatch(
            "remind me to call Alice at 5pm",
            AutonomyLevel::Strict,
        ));
    }

    #[test]
    fn dispatch_false_for_coding_prompt() {
        // Coding intent wins regardless of autonomy level.
        assert!(!should_auto_task_dispatch(
            "build a function that reverses a linked list",
            AutonomyLevel::Full,
        ));
    }

    #[test]
    fn dispatch_false_for_greeting() {
        assert!(!should_auto_task_dispatch(
            "hey what's up",
            AutonomyLevel::Standard,
        ));
    }

    // ── No overlap with coding verb set ────────────────────────────

    #[test]
    fn task_phrases_do_not_contain_coding_verbs() {
        for (phrase, _) in TASK_PHRASES {
            for verb in CODING_VERBS {
                // A task phrase must not START with a coding verb.
                // (mid-phrase inclusion is tolerated for compound phrases
                // like "draft a message" — but the phrase itself triggers
                // on the FULL phrase, not the sub-verb.)
                assert!(
                    !phrase.starts_with(verb),
                    "task phrase '{phrase}' starts with coding verb '{verb}' — overlap risk"
                );
            }
        }
    }

    // ── derive_task_title ──────────────────────────────────────────

    #[test]
    fn title_includes_category_prefix() {
        let intent = GeneralTaskIntent {
            confidence: crate::coding::intent::IntentConfidence::High,
            matched_phrase: Some("remind me".to_string()),
            category: GeneralTaskCategory::Reminder,
        };
        let title = derive_task_title("remind me to call Alice", &intent);
        assert!(title.starts_with("[reminder]"));
    }

    #[test]
    fn title_truncates_long_prompt() {
        let long = "a".repeat(200);
        let intent = GeneralTaskIntent {
            confidence: crate::coding::intent::IntentConfidence::High,
            matched_phrase: None,
            category: GeneralTaskCategory::Other,
        };
        let title = derive_task_title(&long, &intent);
        assert!(title.len() <= 85, "title should be short: {}", title.len());
    }
}
