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
pub fn extract_deep_links(text: &str) -> Vec<DeepLink> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("](#") {
        let anchor = search_from + rel;
        // Label: walk back to the matching '[' (no nesting — first hit).
        let label_start = match text[..anchor].rfind('[') {
            Some(p) => p,
            None => {
                search_from = anchor + 3;
                continue;
            }
        };
        let label = &text[label_start + 1..anchor];
        // Target: from after "](#" to the closing ')'.
        let target_start = anchor + 3;
        let Some(close_rel) = text[target_start..].find(')') else {
            break; // unterminated — nothing further can parse
        };
        let target = &text[target_start..target_start + close_rel];
        search_from = target_start + close_rel + 1;
        if label.trim().is_empty() || label.contains('\n') {
            continue;
        }
        // kind-id split at the FIRST '-'; both halves non-empty, kind is
        // ascii-alphanumeric/underscore (defends against stray markdown).
        let Some(dash) = target.find('-') else { continue };
        let (kind, id) = (&target[..dash], &target[dash + 1..]);
        if kind.is_empty()
            || id.is_empty()
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            continue;
        }
        // Guard against pathological id lengths flooding the sentinel.
        if id.len() > 128 || label.len() > 200 {
            continue;
        }
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
}
