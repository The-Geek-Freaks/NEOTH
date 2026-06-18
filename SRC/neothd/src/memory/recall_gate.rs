//! GOLD-ADAPT-MEM-09 — recall decision gating.
//!
//! A cheap, pure query classifier that decides *how much* recall a turn needs,
//! so a trivial status/identity query ("hi", "what time is it", "who are you")
//! skips the recall pass entirely, an ordinary query runs a single lane, and a
//! historical/exploratory query ("what did we discuss about X", "remind me…")
//! fans out across lanes. Surfaced via `neoth recall --classify`; the chat
//! auto-recall path (`cli::chat::maybe_recall_block_at`) gates Block::D
//! recall-episode injection on this fn — a Skip-tier turn pays no DB hit.
//!
//! Pure (no I/O), so the tier mapping is unit-tested directly.

/// How much recall a query warrants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallTier {
    /// Status / identity / pleasantry — no memory recall needed.
    Skip,
    /// Ordinary query — one recall lane.
    Single,
    /// Historical / exploratory — fan out across lanes.
    Multi,
}

impl RecallTier {
    pub fn as_str(self) -> &'static str {
        match self {
            RecallTier::Skip => "skip",
            RecallTier::Single => "single",
            RecallTier::Multi => "multi",
        }
    }
}

/// Whole-query cues that mean "no memory needed" — the query is about the
/// system/identity/now, not the operator's stored history.
const SKIP_CUES: &[&str] = &[
    "who are you",
    "who am i",
    "what is your name",
    "whats your name",
    "what time",
    "what's the time",
    "whats the time",
    "what date",
    "what day",
    "how are you",
    "are you there",
    "ping",
    "status",
    "version",
    // ── German (operator's language — CLAUDE.md "Language: Deutsch"). The
    // behaviorally-effective lane: a German status/identity/now turn now Skips
    // the Block::D recall + the episodic lane budget instead of wasting a DB
    // scan. Kept specific so a real German history query does NOT false-Skip
    // (e.g. "welcher tag war der deploy" must stay Single — hence "welcher
    // wochentag", not a bare "welcher tag").
    "wer bist du",
    "wer bin ich",
    "wie heißt du",
    "wie heisst du",
    "wie spät",
    "wie spaet",
    "welches datum",
    "welcher wochentag",
    "wie geht's",
    "wie gehts",
    "wie geht es dir",
    "wie geht es ihnen",
    "bist du da",
    "bist du online",
];

/// Cues that the query reaches into stored history → fan out across lanes.
const MULTI_CUES: &[&str] = &[
    "what did we",
    "did we ever",
    "remind me",
    "last time",
    "previously",
    "earlier you",
    "we discussed",
    "we talked about",
    "remember when",
    "history of",
    "over the past",
    "summarize our",
    "everything about",
    // ── German (operator's language). NOTE: Multi and Single map to the SAME
    // LaneBudget today (recall_lanes::budget_for — only Skip differs), so these
    // currently affect only the `neoth recall --classify` report + future-proof
    // a Multi/Single budget split. Complementary to the conversational-recall
    // GERMAN_OPENERS (first-person "weißt du noch" / "erinnerst du dich", which
    // short-circuit BEFORE Block::D) and deliberately OMIT the documented
    // false-positive "was haben wir" (recall/conversational.rs:65). Cues use
    // contiguous forms incl. the German relative-clause participle+auxiliary
    // cluster ("…was wir besprochen haben").
    "letztes mal",
    "beim letzten mal",
    "verlauf von",
    "zusammenfass",
    "alles was wir",
    "in den letzten tagen",
    "in den letzten wochen",
    "worüber wir",
    "besprochen haben",
    "geredet haben",
    "gesprochen haben",
];

/// Classify a query into a [`RecallTier`]. Case-insensitive substring cues;
/// very short pleasantries (≤ 2 tokens like "hi", "thanks") skip too.
pub fn classify_recall_need(query: &str) -> RecallTier {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return RecallTier::Skip;
    }
    // Short pleasantries / greetings.
    let token_count = q.split_whitespace().count();
    const GREETINGS: &[&str] = &[
        "hi",
        "hello",
        "hey",
        "thanks",
        "thank you",
        "yo",
        "ok",
        "okay",
        // German pleasantries (operator's language). The ≤2-token guard keeps
        // "danke, das hilft jetzt" (a real follow-up) out of the Skip path.
        "hallo",
        "servus",
        "moin",
        "danke",
        "vielen dank",
        "tschüss",
        "tschuss",
    ];
    if token_count <= 2
        && GREETINGS
            .iter()
            .any(|g| q == *g || q.starts_with(&format!("{g} ")))
    {
        return RecallTier::Skip;
    }
    if SKIP_CUES.iter().any(|c| q.contains(c)) {
        return RecallTier::Skip;
    }
    if MULTI_CUES.iter().any(|c| q.contains(c)) {
        return RecallTier::Multi;
    }
    RecallTier::Single
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_status_identity_and_greetings() {
        for q in [
            "hi",
            "hello there",
            "thanks",
            "who are you",
            "what time is it",
            "ping",
            "status",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Skip,
                "{q:?} should skip"
            );
        }
        assert_eq!(classify_recall_need("   "), RecallTier::Skip);
    }

    #[test]
    fn multi_for_historical_queries() {
        for q in [
            "what did we discuss about rust",
            "remind me what the plan was",
            "summarize our last session",
            "everything about the cluster design",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Multi,
                "{q:?} should fan out"
            );
        }
    }

    #[test]
    fn single_for_ordinary_queries() {
        for q in [
            "how does the WAL writer rotate segments",
            "rust borrow checker rules",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Single,
                "{q:?} ordinary"
            );
        }
    }

    #[test]
    fn tier_labels_stable() {
        assert_eq!(RecallTier::Skip.as_str(), "skip");
        assert_eq!(RecallTier::Single.as_str(), "single");
        assert_eq!(RecallTier::Multi.as_str(), "multi");
    }

    // ── German i18n (operator's language — CLAUDE.md "Language: Deutsch") ──

    #[test]
    fn german_skip_cues_and_greetings_skip() {
        for q in [
            "hallo",
            "servus",
            "danke",
            "vielen dank",
            "tschüss",
            "wer bist du",
            "wie heißt du",
            "wie spät ist es",
            "wie geht's dir",
            "bist du da",
            "welches datum ist heute",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Skip,
                "{q:?} should skip"
            );
        }
    }

    #[test]
    fn german_history_cues_fan_out_to_multi() {
        for q in [
            "was war beim letzten mal das thema",
            "worüber wir gestern geredet haben",
            "gib mir den verlauf von dem cluster projekt",
            "in den letzten tagen",
            "alles was wir über rust gemacht haben",
            "gib mir eine zusammenfassung unserer session",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Multi,
                "{q:?} should fan out"
            );
        }
    }

    #[test]
    fn german_ordinary_query_stays_single_no_false_skip() {
        for q in [
            "wie funktioniert der wal writer",
            "erklär mir den borrow checker",
            // History-ish wording but no cue + NOT a status cue: "welcher tag"
            // alone must NOT false-Skip (only "welcher wochentag" Skips).
            "welcher tag war der deploy",
            // A real follow-up that merely opens with "danke" is >2 tokens →
            // not a greeting-Skip.
            "danke das hilft jetzt weiter",
        ] {
            assert_eq!(
                classify_recall_need(q),
                RecallTier::Single,
                "{q:?} ordinary"
            );
        }
    }
}
