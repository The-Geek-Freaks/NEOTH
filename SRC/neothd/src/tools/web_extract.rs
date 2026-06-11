//! GOLD-ADOPT-04 — native CSS web extraction + adaptive re-find (Scrapling
//! pattern, pure Rust via the `scraper` crate).
//!
//! Pure + synchronous + network-free: every function here takes an HTML
//! STRING + a CSS selector and returns matched text / attributes, so it is
//! trivially unit-testable on a mock document. The fetch + cache live in
//! [`crate::tools::web_selector_cache`].
//!
//! **Adaptive re-find** (Scrapling's signature feature, NEOTH-minimal): an
//! [`ElementFingerprint`] captured from the first match lets [`refind`] relocate
//! the element by a deterministic similarity score when the site's structure
//! shifts and the stored selector stops matching — no ML, no embeddings, just a
//! 10-point heuristic over tag / id / classes / text / position.

use anyhow::Result;
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};

/// Total injected-bytes ceiling across all matched elements (mirrors
/// `web_fetch::MAX_EXTRACTED_BYTES` — keeps prompt cost bounded).
pub const EXTRACT_OUTPUT_CEILING: usize = 200_000;

/// Minimum similarity score (of 10) for [`refind`] to accept a relocated
/// element. 4 ≈ "matches on classes OR id plus one structural signal".
pub const REFIND_MIN_SCORE: u32 = 4;

/// How many chars of an element's text to fingerprint.
const TEXT_PREFIX_LEN: usize = 48;

/// Parse a CSS selector, mapping `scraper`'s non-`Error` `SelectorErrorKind`
/// into an `anyhow::Error` (the `?` operator can't be used on it directly).
fn parse_selector(css: &str) -> Result<Selector> {
    Selector::parse(css).map_err(|e| anyhow::anyhow!("invalid CSS selector `{css}`: {e:?}"))
}

/// Extract the text content of every element matching `css`. `Ok(vec![])` on no
/// match (NOT an error); `Err` only on an invalid selector. Output is capped at
/// [`EXTRACT_OUTPUT_CEILING`] total bytes.
pub fn extract_text(html: &str, css: &str) -> Result<Vec<String>> {
    let doc = Html::parse_document(html);
    let sel = parse_selector(css)?;
    let mut out = Vec::new();
    let mut total = 0usize;
    for el in doc.select(&sel) {
        let remaining = EXTRACT_OUTPUT_CEILING.saturating_sub(total);
        if remaining == 0 {
            break;
        }
        let mut text: String = el.text().collect::<String>().trim().to_string();
        // HARD ceiling (review F): truncate the element that would overflow to
        // a char boundary within the remaining budget, then stop — `total`
        // never exceeds EXTRACT_OUTPUT_CEILING.
        if text.len() > remaining {
            let mut end = remaining;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            out.push(text);
            break;
        }
        total += text.len();
        out.push(text);
    }
    Ok(out)
}

/// Extract attribute `attr` from every element matching `css`. Elements lacking
/// the attribute are skipped.
pub fn extract_attr(html: &str, css: &str, attr: &str) -> Result<Vec<String>> {
    let doc = Html::parse_document(html);
    let sel = parse_selector(css)?;
    let mut out = Vec::new();
    let mut total = 0usize;
    for el in doc.select(&sel) {
        if let Some(v) = el.value().attr(attr) {
            // Hard ceiling: a truncated attribute (e.g. a half URL) is useless,
            // so drop the one that would overflow rather than emit garbage.
            if total + v.len() > EXTRACT_OUTPUT_CEILING {
                break;
            }
            total += v.len();
            out.push(v.to_string());
        }
    }
    Ok(out)
}

/// A deterministic structural fingerprint of one element — enough to relocate
/// it by similarity if its selector later breaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementFingerprint {
    pub tag: String,
    /// First [`TEXT_PREFIX_LEN`] chars of the element's trimmed text.
    pub text_prefix: Option<String>,
    /// Class tokens, sorted + deduped (stable comparison).
    pub class_tokens: Vec<String>,
    pub id: Option<String>,
    /// Index among same-tag siblings under the parent (positional anchor).
    pub nth_of_tag_in_parent: Option<usize>,
    pub parent_tag: Option<String>,
    pub parent_class_tokens: Vec<String>,
}

fn sorted_classes(el: &ElementRef) -> Vec<String> {
    let mut c: Vec<String> = el.value().classes().map(|s| s.to_string()).collect();
    c.sort();
    c.dedup();
    c
}

fn text_prefix_of(el: &ElementRef) -> Option<String> {
    let t: String = el.text().collect::<String>().trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(TEXT_PREFIX_LEN).collect())
    }
}

fn parent_element<'a>(el: &ElementRef<'a>) -> Option<ElementRef<'a>> {
    el.parent().and_then(ElementRef::wrap)
}

/// Index of `el` among its same-tag element siblings under `parent`.
fn nth_of_tag(parent: &ElementRef, el: &ElementRef) -> Option<usize> {
    let tag = el.value().name();
    parent
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|c| c.value().name() == tag)
        .position(|c| c.id() == el.id())
}

fn fingerprint_of(el: &ElementRef) -> ElementFingerprint {
    let parent = parent_element(el);
    ElementFingerprint {
        tag: el.value().name().to_string(),
        text_prefix: text_prefix_of(el),
        class_tokens: sorted_classes(el),
        id: el.value().id().map(|s| s.to_string()),
        nth_of_tag_in_parent: parent.as_ref().and_then(|p| nth_of_tag(p, el)),
        parent_tag: parent.as_ref().map(|p| p.value().name().to_string()),
        parent_class_tokens: parent.as_ref().map(sorted_classes).unwrap_or_default(),
    }
}

/// Build a fingerprint from the FIRST element matching `css`. `Ok(None)` when
/// the selector matches nothing.
pub fn fingerprint_first(html: &str, css: &str) -> Result<Option<ElementFingerprint>> {
    let doc = Html::parse_document(html);
    let sel = parse_selector(css)?;
    Ok(doc.select(&sel).next().map(|el| fingerprint_of(&el)))
}

/// Jaccard similarity of two sorted token sets (0.0..=1.0). Empty ∩ empty = 1.
fn jaccard(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.iter().filter(|x| b.contains(x)).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f32 / union as f32
    }
}

/// Score a candidate element against the fingerprint (max 10 points).
fn score_candidate(fp: &ElementFingerprint, el: &ElementRef) -> u32 {
    let mut score = 0u32;
    // +2 same id
    if let (Some(want), Some(have)) = (&fp.id, el.value().id()) {
        if want == have {
            score += 2;
        }
    }
    // +3 class overlap (Jaccard ≥ 0.5)
    if !fp.class_tokens.is_empty() && jaccard(&fp.class_tokens, &sorted_classes(el)) >= 0.5 {
        score += 3;
    }
    // +2 same text prefix
    if let (Some(want), Some(have)) = (&fp.text_prefix, text_prefix_of(el)) {
        if want == &have {
            score += 2;
        }
    }
    let parent = parent_element(el);
    // +1 same positional index among same-tag siblings
    if let (Some(want), Some(p)) = (fp.nth_of_tag_in_parent, parent.as_ref()) {
        if nth_of_tag(p, el) == Some(want) {
            score += 1;
        }
    }
    // +1 same parent tag
    if let (Some(want), Some(p)) = (&fp.parent_tag, parent.as_ref()) {
        if want == p.value().name() {
            score += 1;
        }
    }
    // +1 parent class overlap (Jaccard ≥ 0.5)
    if !fp.parent_class_tokens.is_empty() {
        if let Some(p) = parent.as_ref() {
            if jaccard(&fp.parent_class_tokens, &sorted_classes(p)) >= 0.5 {
                score += 1;
            }
        }
    }
    score
}

/// Derive a fresh CSS selector for a relocated element: `tag[id="…"]`, else
/// `tag[class~="…"]`, else bare `tag`.
///
/// GR-019 — attribute selectors are used instead of `tag#id` / `tag.firstClass`
/// because Tailwind-style ids/classes routinely carry CSS-special characters
/// (`md:flex`, `w-1/2`, `text-[#fff]`). A bare `.md:flex` is INVALID CSS — the
/// `:` opens a pseudo-class — so `Selector::parse` would error and the recovery
/// path (`extract_text(raw, &new_sel)?`) would hard-fail on every such page. An
/// attribute selector needs no CSS-identifier escaping; only the quoted value's
/// `"` / `\` are special (handled by [`css_attr_value_escape`]), and `~=`
/// matches the single class as a whitespace-separated token.
fn derive_selector(el: &ElementRef) -> String {
    let tag = el.value().name();
    if let Some(id) = el.value().id() {
        return format!("{tag}[id=\"{}\"]", css_attr_value_escape(id));
    }
    if let Some(first) = el.value().classes().next() {
        return format!("{tag}[class~=\"{}\"]", css_attr_value_escape(first));
    }
    tag.to_string()
}

/// Escape a string for use inside a double-quoted CSS attribute value: per the
/// CSS Syntax module only the backslash and the closing quote are special there.
fn css_attr_value_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Relocate the fingerprinted element in `html` when its old selector broke.
/// Scans all elements of the fingerprint's tag, scores each, and returns the
/// best `(new_selector, score)` when the top score crosses
/// [`REFIND_MIN_SCORE`]; ties break on document order (first wins). `None` when
/// nothing scores high enough.
pub fn refind(html: &str, fp: &ElementFingerprint) -> Option<(String, f32)> {
    let doc = Html::parse_document(html);
    // A bare-tag selector enumerates every candidate of the right tag.
    let sel = Selector::parse(&fp.tag).ok()?;
    let mut best: Option<(ElementRef, u32)> = None;
    for el in doc.select(&sel) {
        let s = score_candidate(fp, &el);
        // Strictly-greater keeps the FIRST element at a given score (doc order).
        if best.as_ref().map(|(_, bs)| s > *bs).unwrap_or(true) {
            best = Some((el, s));
        }
    }
    match best {
        Some((el, s)) if s >= REFIND_MIN_SCORE => Some((derive_selector(&el), s as f32 / 10.0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_text_matches_class_selector() {
        let html = r#"<div><span class="price">$9.99</span></div>"#;
        assert_eq!(extract_text(html, "span.price").unwrap(), vec!["$9.99"]);
    }

    #[test]
    fn extract_text_returns_empty_on_no_match() {
        let html = r#"<div><span class="price">$9.99</span></div>"#;
        assert_eq!(extract_text(html, "span.missing").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn extract_text_errors_on_invalid_selector() {
        let err = extract_text("<p>x</p>", ">>>bad").unwrap_err();
        assert!(err.to_string().contains("invalid CSS selector"), "{err}");
    }

    #[test]
    fn extract_attr_returns_hrefs() {
        let html = r#"<a class="dl" href="/file.zip">Download</a>"#;
        assert_eq!(extract_attr(html, "a.dl", "href").unwrap(), vec!["/file.zip"]);
    }

    #[test]
    fn fingerprint_first_captures_structure() {
        let html = r#"<div class="wrapper"><span class="price tag">$9</span></div>"#;
        let fp = fingerprint_first(html, "span.price").unwrap().unwrap();
        assert_eq!(fp.tag, "span");
        assert_eq!(fp.class_tokens, vec!["price", "tag"]); // sorted
        assert_eq!(fp.parent_tag.as_deref(), Some("div"));
        assert_eq!(fp.parent_class_tokens, vec!["wrapper"]);
        assert_eq!(fp.text_prefix.as_deref(), Some("$9"));
    }

    #[test]
    fn refind_locates_moved_element() {
        // Original: the price span is the 1st child.
        let v1 = r#"<div class="card"><span class="price">$9</span></div>"#;
        let fp = fingerprint_first(v1, "span.price").unwrap().unwrap();
        // v2: site changed — the span moved behind a new label, selector
        // `span.price` would be unaffected here, so simulate a true break by
        // changing the wrapper but keeping the element's own signals.
        let v2 = r#"<section><div class="card"><em>Now:</em><span class="price">$9</span></div></section>"#;
        let (new_sel, score) = refind(v2, &fp).expect("should relocate");
        assert!(score >= REFIND_MIN_SCORE as f32 / 10.0);
        assert!(new_sel.starts_with("span"), "got {new_sel}");
    }

    #[test]
    fn refind_returns_none_when_no_good_match() {
        let v1 = r#"<div class="card"><span class="price">$9</span></div>"#;
        let fp = fingerprint_first(v1, "span.price").unwrap().unwrap();
        // Completely unrelated document — no span at all.
        let v2 = r#"<p class="totally-different">hello world</p>"#;
        assert!(refind(v2, &fp).is_none());
    }

    #[test]
    fn derive_selector_handles_tailwind_classes_gr019() {
        // GR-019 — a Tailwind class carries CSS-special chars (`:`, `/`). The old
        // `tag.firstClass` produced `span.md:flex` (INVALID CSS → recovery
        // hard-error). The attribute-selector form parses AND re-matches.
        let html = r#"<span class="md:flex w-1/2">x</span>"#;
        let doc = Html::parse_fragment(html);
        let sel = Selector::parse("span").unwrap();
        let el = doc.select(&sel).next().unwrap();
        let derived = derive_selector(&el);
        assert_eq!(derived, r#"span[class~="md:flex"]"#);
        // The derived selector MUST be valid CSS (the bare `.md:flex` was not).
        let resel = Selector::parse(&derived).expect("derived selector must parse");
        assert_eq!(doc.select(&resel).count(), 1, "must re-match the same element");
        // End-to-end: extract_text no longer errors on the relocated selector.
        assert_eq!(extract_text(html, &derived).unwrap(), vec!["x"]);
    }

    #[test]
    fn derive_selector_quote_escapes_value_gr019() {
        // A class containing a double-quote must not break out of the attr value.
        let html = r#"<a class='ab&quot;cd'>y</a>"#;
        let doc = Html::parse_fragment(html);
        let sel = Selector::parse("a").unwrap();
        let el = doc.select(&sel).next().unwrap();
        let derived = derive_selector(&el);
        assert!(Selector::parse(&derived).is_ok(), "escaped selector must parse: {derived}");
    }

    #[test]
    fn extract_output_ceiling_is_enforced() {
        let body: String = (0..100)
            .map(|_| format!("<p class=\"x\">{}</p>", "z".repeat(3000)))
            .collect();
        let html = format!("<div>{body}</div>");
        let out = extract_text(&html, "p.x").unwrap();
        let total: usize = out.iter().map(|s| s.len()).sum();
        // HARD ceiling: the overflowing element is truncated to fit, so the
        // total NEVER exceeds the ceiling.
        assert!(total <= EXTRACT_OUTPUT_CEILING, "total {total}");
    }

    #[test]
    fn jaccard_basics() {
        assert_eq!(jaccard(&[], &[]), 1.0);
        let a = vec!["x".to_string(), "y".to_string()];
        let b = vec!["x".to_string(), "y".to_string()];
        assert_eq!(jaccard(&a, &b), 1.0);
        let c = vec!["x".to_string(), "z".to_string()];
        assert!((jaccard(&a, &c) - (1.0 / 3.0)).abs() < 1e-6);
    }
}
