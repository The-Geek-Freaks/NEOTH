//! GOLD-ADAPT-MEM-09 — recall decision gating.
//!
//! A cheap, pure query classifier that decides *how much* recall a turn needs,
//! so a trivial status/identity query ("hi", "what time is it", "who are you")
//! skips the recall pass entirely, an ordinary query runs a single lane, and a
//! historical/exploratory query ("what did we discuss about X", "remind me…")
//! fans out across lanes. Surfaced today via `neoth recall --classify`; the
//! chat auto-recall path consumes the same fn in a later slice.
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
    const GREETINGS: &[&str] = &["hi", "hello", "hey", "thanks", "thank you", "yo", "ok", "okay"];
    if token_count <= 2 && GREETINGS.iter().any(|g| q == *g || q.starts_with(&format!("{g} "))) {
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
        for q in ["hi", "hello there", "thanks", "who are you", "what time is it", "ping", "status"] {
            assert_eq!(classify_recall_need(q), RecallTier::Skip, "{q:?} should skip");
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
            assert_eq!(classify_recall_need(q), RecallTier::Multi, "{q:?} should fan out");
        }
    }

    #[test]
    fn single_for_ordinary_queries() {
        for q in ["how does the WAL writer rotate segments", "rust borrow checker rules"] {
            assert_eq!(classify_recall_need(q), RecallTier::Single, "{q:?} ordinary");
        }
    }

    #[test]
    fn tier_labels_stable() {
        assert_eq!(RecallTier::Skip.as_str(), "skip");
        assert_eq!(RecallTier::Single.as_str(), "single");
        assert_eq!(RecallTier::Multi.as_str(), "multi");
    }
}
