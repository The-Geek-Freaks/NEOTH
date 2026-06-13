//! GOLD-ADAPT-ODY-25 (NEOTH-native) — keyword search over session cards.
//!
//! ODY-25's source does FTS5 over raw transcripts, but NEOTH compresses every
//! session into a lossy [`HindsightCard`] (topics + opening/closing utterance +
//! one-line summary + optional title) — the raw turns are not persisted
//! searchable. So this searches the *card* corpus instead: an operator can ask
//! "which past session was about X" and get ranked sessions, even though there
//! are no transcript rows to surface before/after context from.
//!
//! Pure over a slice of cards (the CLI loads them via
//! [`crate::memory::hindsight::list_cards`]), so ranking is unit-tested without
//! touching disk.

use crate::memory::hindsight::HindsightCard;

/// One scored session hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMatch<'a> {
    pub card: &'a HindsightCard,
    pub score: u32,
    /// Which card fields a query term hit, for the `--output table` why-line.
    pub matched_fields: Vec<&'static str>,
}

fn push_once(fields: &mut Vec<&'static str>, f: &'static str) {
    if !fields.contains(&f) {
        fields.push(f);
    }
}

/// Field weights: a hit in the (LLM-or-deterministic) title or the ranked
/// topics is a stronger signal than the freeform utterances.
const W_NAME: u32 = 4;
const W_TOPICS: u32 = 3;
const W_SUMMARY: u32 = 2;
const W_UTTERANCE: u32 = 1;

/// Case-insensitive keyword search. Every whitespace-split query term that
/// appears in a card field adds that field's weight; cards scoring 0 are
/// dropped. Results are sorted score-desc, then most-recent-first, then capped
/// to `limit`.
pub fn search_session_cards<'a>(
    cards: &'a [HindsightCard],
    query: &str,
    limit: usize,
) -> Vec<SessionMatch<'a>> {
    let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
    if terms.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<SessionMatch<'a>> = Vec::new();
    for card in cards {
        let name = card.display_name.as_deref().unwrap_or("").to_lowercase();
        let topics = card.top_topics.join(" ").to_lowercase();
        let summary = card.one_line_summary.to_lowercase();
        let utterances = format!(
            "{} {}",
            card.opening_utterance, card.closing_utterance
        )
        .to_lowercase();

        let mut score = 0u32;
        let mut fields: Vec<&'static str> = Vec::new();
        for t in &terms {
            let t = t.as_str();
            if name.contains(t) {
                score += W_NAME;
                push_once(&mut fields, "name");
            }
            if topics.contains(t) {
                score += W_TOPICS;
                push_once(&mut fields, "topics");
            }
            if summary.contains(t) {
                score += W_SUMMARY;
                push_once(&mut fields, "summary");
            }
            if utterances.contains(t) {
                score += W_UTTERANCE;
                push_once(&mut fields, "utterances");
            }
        }
        if score > 0 {
            out.push(SessionMatch {
                card,
                score,
                matched_fields: fields,
            });
        }
    }
    out.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.card.started_at_unix.cmp(&a.card.started_at_unix))
    });
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: &str, started: i64, name: Option<&str>, topics: &[&str], summary: &str, open: &str) -> HindsightCard {
        HindsightCard {
            session_id: id.to_string(),
            started_at_unix: started,
            ended_at_unix: started + 60,
            turn_count: 4,
            operator_turn_count: 2,
            agent_turn_count: 2,
            top_topics: topics.iter().map(|t| t.to_string()).collect(),
            opening_utterance: open.to_string(),
            closing_utterance: String::new(),
            one_line_summary: summary.to_string(),
            display_name: name.map(|s| s.to_string()),
        }
    }

    #[test]
    fn ranks_by_field_weight() {
        let cards = vec![
            card("a", 100, None, &["misc"], "talked about rust", "hi"),       // summary hit (2)
            card("b", 200, Some("Rust deep dive"), &["go"], "x", "y"),         // name hit (4)
            card("c", 300, None, &["rust", "async"], "x", "y"),               // topics hit (3)
        ];
        let hits = search_session_cards(&cards, "rust", 10);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].card.session_id, "b", "name weight highest");
        assert_eq!(hits[1].card.session_id, "c", "topics next");
        assert_eq!(hits[2].card.session_id, "a", "summary last");
        assert!(hits[0].matched_fields.contains(&"name"));
    }

    #[test]
    fn multi_term_accumulates_score() {
        let cards = vec![
            card("a", 100, None, &["rust"], "x", "y"),                 // 1 term hits topics = 3
            card("b", 200, None, &["rust", "async"], "x", "y"),       // both terms hit topics = 6
        ];
        let hits = search_session_cards(&cards, "rust async", 10);
        assert_eq!(hits[0].card.session_id, "b", "more terms matched ranks higher");
    }

    #[test]
    fn no_match_is_empty_and_blank_query_is_empty() {
        let cards = vec![card("a", 100, None, &["go"], "x", "y")];
        assert!(search_session_cards(&cards, "kotlin", 10).is_empty());
        assert!(search_session_cards(&cards, "   ", 10).is_empty());
    }

    #[test]
    fn ties_break_by_most_recent_then_limit_applies() {
        let cards = vec![
            card("old", 100, None, &["rust"], "x", "y"),
            card("new", 999, None, &["rust"], "x", "y"),
        ];
        let hits = search_session_cards(&cards, "rust", 1);
        assert_eq!(hits.len(), 1, "limit truncates");
        assert_eq!(hits[0].card.session_id, "new", "newer wins the tie");
    }

    #[test]
    fn search_is_case_insensitive() {
        let cards = vec![card("a", 100, Some("RUST Things"), &[], "x", "y")];
        assert_eq!(search_session_cards(&cards, "rust", 10).len(), 1);
    }
}
