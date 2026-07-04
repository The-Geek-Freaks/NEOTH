//! GOLD-ADAPT-ODY-12/14 — cross-entity deep links + UI-control events.
//!
//! One mechanism serves both items (spec synthesis — the upstream split
//! LLM→UI events and inline links across two web-renderer features; in
//! Slint they collapse naturally): the model emits markdown-shaped
//! `[label](#kind-id)` references in its reply, the daemon extracts them
//! post-completion and ships them as a `links` array on the extended
//! done-sentinel (additive JSON field — old consumers ignore it). The
//! GUI renders them as clickable chips under the reply; `nav-<panel>`
//! chips ARE the UI-control events (navigate), entity kinds
//! (`kanban-<task_id>`) navigate + focus.
//!
//! Text stays untouched — terminal/channel consumers just see plain
//! markdown that degrades gracefully.

use serde::Serialize;

/// One extracted deep link. Serialized verbatim into the done-sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeepLink {
    pub label: String,
    pub kind: String,
    pub id: String,
}

/// System-prompt fragment injected ONLY on the GUI stream path
/// (`--stream`): terminal + channel surfaces never see it, so the model
/// doesn't emit anchors nobody can click.
pub const DEEP_LINK_PROMPT: &str = "\
UI deep links: when you reference a NEOTH entity or suggest opening a \
panel, you may mark it as [label](#kind-id). Supported: \
[label](#kanban-<task_id>) for coding-board tasks, and \
[label](#nav-<panel>) to open a panel (panels: chat, memory, \
hemispheres, channels, coding, agents, automation, privacy, plugins, \
cluster, resources, doctor, loops, config). Use at most a few per \
reply and only for entities you actually mentioned; otherwise write \
plain text.";

/// Extract every `[label](#kind-id)` occurrence, in order. Malformed
/// candidates (empty label, no `-` separator, unterminated paren) are
/// skipped silently — the model's text is untrusted input.
/// Hard cap on chips per reply — a hostile/looping model repeating
/// anchors must not flood the sentinel line or the GUI chip row.
const MAX_LINKS: usize = 8;

pub fn extract_deep_links(text: &str) -> Vec<DeepLink> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("](#") {
        if out.len() >= MAX_LINKS {
            break;
        }
        let anchor = search_from + rel;
        // Advance past this candidate FIRST — every reject path below
        // must continue the scan (error-hunt wave s4: the old
        // `break`-on-unterminated let one bad anchor greedily absorb a
        // later ')' and swallow valid links behind it).
        search_from = anchor + 3;
        // Label: walk back to the matching '[' (no nesting — first hit).
        let Some(label_start) = text[..anchor].rfind('[') else {
            continue;
        };
        let label = &text[label_start + 1..anchor];
        // Target: from after "](#" to the closing ')'.
        let target_start = anchor + 3;
        let Some(close_rel) = text[target_start..].find(')') else {
            continue; // unterminated candidate — keep scanning
        };
        let target = &text[target_start..target_start + close_rel];
        if label.trim().is_empty() || label.contains('\n') {
            continue;
        }
        // kind-id split at the FIRST '-'; both halves non-empty. kind is
        // ascii-lower/digit/underscore; id is a tight token charset —
        // this ALSO defuses the greedy-')' case (an id that swallowed
        // ` [good](#nav` fails the charset and is rejected).
        let Some(dash) = target.find('-') else { continue };
        let (kind, id) = (&target[..dash], &target[dash + 1..]);
        if kind.is_empty()
            || id.is_empty()
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            continue;
        }
        // Guard against pathological lengths flooding the sentinel.
        if id.len() > 128 || label.len() > 200 {
            continue;
        }
        // Only after a fully valid candidate: resume AFTER its ')'.
        search_from = target_start + close_rel + 1;
        out.push(DeepLink {
            label: label.trim().to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_kanban_and_nav_links_in_order() {
        let text = "See [task 42](#kanban-42), then open [the board](#nav-coding).";
        let links = extract_deep_links(text);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].label, "task 42");
        assert_eq!(links[0].kind, "kanban");
        assert_eq!(links[0].id, "42");
        assert_eq!(links[1].kind, "nav");
        assert_eq!(links[1].id, "coding");
    }

    #[test]
    fn plain_markdown_urls_are_not_deep_links() {
        let text = "Read [the docs](https://example.com) and [rfc](#x).";
        assert!(extract_deep_links(text).is_empty());
    }

    #[test]
    fn malformed_candidates_are_skipped() {
        // empty label / missing dash / bad kind chars / unterminated
        let text = "[](#kanban-1) [a](#nodash) [b](#Kind-2) [c](#kanban-3";
        assert!(extract_deep_links(text).is_empty());
    }

    #[test]
    fn id_may_contain_further_dashes() {
        let links = extract_deep_links("[s](#session-2026-07-04-a1)");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].kind, "session");
        assert_eq!(links[0].id, "2026-07-04-a1");
    }

    #[test]
    fn no_links_returns_empty() {
        assert!(extract_deep_links("plain reply, no anchors").is_empty());
    }

    /// Error-hunt wave s4: an unterminated anchor must not greedily
    /// absorb a later valid link's ')' — the bad candidate is rejected
    /// (id charset) and the good link behind it still extracts.
    #[test]
    fn unterminated_anchor_does_not_swallow_later_valid_link() {
        let links = extract_deep_links("[bad](#kanban-1 [good](#nav-coding)");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].kind, "nav");
        assert_eq!(links[0].id, "coding");
    }

    #[test]
    fn chip_count_is_capped() {
        let flood = "[x](#kanban-1) ".repeat(40);
        assert_eq!(extract_deep_links(&flood).len(), 8);
    }

    #[test]
    fn id_charset_rejects_whitespace_and_brackets() {
        assert!(extract_deep_links("[a](#kanban-4 2)").is_empty());
        assert!(extract_deep_links("[a](#kanban-[42])").is_empty());
    }
}
