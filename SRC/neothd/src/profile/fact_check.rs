//! QM-19 — fact-check wrapper around `claim_guard`.
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` §3.1 "fact-check"
//! ADOPT-AS-CORE. Closes the gap where NEOTH's existing H1/H2/H5/M1/M2
//! claim guard only fires post-extraction on profile deltas — there
//! was no operator-facing surface that says "give me a fact-check
//! report on THIS claim or paragraph". QM-19 ships the wrapper.
//!
//! ## What this module is
//!
//! `assess(claim_text)` → [`FactCheckReport`]. Pure decomposition of
//! the claim into atomic propositions + a per-proposition pattern-
//! based confidence + the operator-readable WAS-IS-MAYBE verdict.
//! No LLM call in v0.1 — the academic-research-skills repo's full
//! Crossref+OpenAlex+SemanticScholar triangulation is the follow-up
//! when the citation_check helper lands (QM-18). Today we ship the
//! deterministic surface that operator + sub-agents can call without
//! a network round-trip.
//!
//! ## What it does NOT do (yet)
//!
//! - External citation lookup (QM-18 follow-up; needs the outbound
//!   HTTP surface allowlisted in `tests/no_outbound_network.rs`).
//! - LLM-driven extraction of claims (claim_guard already does that
//!   on the profile-delta surface; this module is for ad-hoc text).
//! - Temporal verification (QM-20 ships `temporal_guard` as a
//!   sibling pass after this one).
//!
//! ## Composition
//!
//! ```text
//! operator text  →  decompose_propositions(text)
//!                →  for each prop: classify_confidence(prop)
//!                →  FactCheckReport { propositions, verdict }
//! ```
//!
//! Operators invoke via `neoth profile fact-check "<text>"` (CLI
//! surface follow-up) or programmatically via `assess(text)`. The
//! report renders cleanly as JSON for tooling + Markdown for chat.

use serde::{Deserialize, Serialize};

/// QM-19: classifier confidence the fact-checker assigns to one
/// proposition. Deterministic shape; operators in different locales
/// see the same buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The proposition matches a well-known shape (concrete date,
    /// numeric fact, public-record entity) that the operator can
    /// usually verify in one search.
    Verifiable,
    /// The proposition makes a falsifiable claim but lacks the
    /// concrete anchors (date / source / number) that would make
    /// verification one-step. Operator should ask the speaker for
    /// the anchor before treating it as fact.
    Plausible,
    /// The proposition is opinion / speculation / "I think" /
    /// hedge-laden prose. Treat as the speaker's view, not a fact.
    Opinion,
    /// The proposition contradicts a high-confidence neighbour
    /// proposition in the same text, OR contains a recognised
    /// rhetoric pattern (absolutism, slippery-slope). Flag for
    /// review.
    Suspect,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Verifiable => "verifiable",
            Confidence::Plausible => "plausible",
            Confidence::Opinion => "opinion",
            Confidence::Suspect => "suspect",
        }
    }
}

/// QM-19: one atomic proposition extracted from the operator text +
/// its classifier verdict. Atoms are sentence-level; multi-sentence
/// claims decompose to one entry per sentence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposition {
    /// The sentence text exactly as it appeared in the input.
    pub text: String,
    /// Confidence bucket the deterministic classifier assigned.
    pub confidence: Confidence,
    /// One-line rationale citing which pattern triggered the
    /// classification — operator can audit the call without having
    /// to grep the rules.
    pub rationale: String,
}

/// QM-19: rollup verdict for the whole input. Three states mirror
/// the academic-research-skills `fact-check` mode's output shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every proposition is verifiable or plausible; no suspect
    /// content. Operator can ship the claim without revision.
    Clean,
    /// Mix of plausible + opinion, OR exclusively opinion. Operator
    /// needs to frame the text as opinion ("I think" / "in my view")
    /// before treating it as fact.
    NeedsFraming,
    /// At least one proposition is `Suspect`. Operator must revise
    /// before shipping; review the flagged sentences.
    NeedsRevision,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::NeedsFraming => "needs_framing",
            Verdict::NeedsRevision => "needs_revision",
        }
    }
}

/// QM-19 fact-check report. JSON-stable shape for `neoth profile
/// fact-check --output json` + downstream tooling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactCheckReport {
    pub propositions: Vec<Proposition>,
    pub verdict: Verdict,
}

impl FactCheckReport {
    /// Count propositions whose confidence matches the given bucket.
    /// Cheap; used by the CLI render to produce a one-line summary.
    pub fn count(&self, bucket: Confidence) -> usize {
        self.propositions
            .iter()
            .filter(|p| p.confidence == bucket)
            .count()
    }
}

/// QM-19: split text into atomic propositions. Sentence-level via
/// `. ! ?` terminators with a minimum-length guard (drops fragments
/// shorter than 6 chars which are usually parsing artefacts like
/// "Inc."). Pure function; no allocation beyond the output.
pub fn decompose_propositions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        current.push(c);
        if matches!(c, '.' | '!' | '?') {
            let trimmed = current.trim();
            if trimmed.len() >= 6 {
                out.push(trimmed.to_string());
            }
            current.clear();
        }
    }
    let leftover = current.trim();
    if leftover.len() >= 6 {
        out.push(leftover.to_string());
    }
    out
}

/// QM-19: deterministic per-proposition confidence classifier. Pure
/// function; uses pattern-based heuristics that operate without an
/// LLM call.
///
/// Pattern catalogue (most-specific first so the suspect path
/// dominates when both opinion + suspect signals fire):
///
/// - **Suspect**: absolutism ("always", "never", "everyone",
///   "nobody"), slippery-slope ("will inevitably", "leads directly
///   to"), gish-gallop ("countless examples", "you'd be a fool to
///   deny").
/// - **Opinion**: hedges ("I think", "I believe", "in my view",
///   "personally", "seems to me").
/// - **Verifiable**: contains a concrete anchor — 4-digit year /
///   number with unit / proper-noun entity / explicit citation.
/// - **Plausible**: the residual — claim is falsifiable but lacks
///   the verifiable-style anchors.
pub fn classify_confidence(proposition: &str) -> (Confidence, &'static str) {
    let lower = proposition.to_lowercase();
    // ── Suspect (highest priority) ────────────────────────────────────
    let suspect_patterns: &[(&str, &str)] = &[
        ("always", "absolutism: 'always' is rarely literally true"),
        ("never", "absolutism: 'never' is rarely literally true"),
        ("everyone", "absolutism: 'everyone' over-generalises"),
        ("nobody", "absolutism: 'nobody' over-generalises"),
        ("will inevitably", "slippery-slope: predicted inevitability"),
        (
            "leads directly to",
            "slippery-slope: causal chain claimed without evidence",
        ),
        (
            "countless examples",
            "gish-gallop: vague mass-evidence claim",
        ),
        ("you'd be a fool", "ad-hominem framing"),
        ("anyone who disagrees", "ad-hominem framing"),
    ];
    for (pat, why) in suspect_patterns {
        if lower.contains(pat) {
            return (Confidence::Suspect, why);
        }
    }

    // ── Opinion ────────────────────────────────────────────────────────
    let opinion_patterns: &[(&str, &str)] = &[
        ("i think", "hedge: 'I think' marks speaker opinion"),
        ("i believe", "hedge: 'I believe' marks speaker opinion"),
        ("in my view", "hedge: 'in my view' marks speaker opinion"),
        ("personally", "hedge: 'personally' marks speaker opinion"),
        ("seems to me", "hedge: 'seems to me' marks speaker opinion"),
        ("ich denke", "hedge (DE): 'ich denke' marks speaker opinion"),
        (
            "meiner meinung",
            "hedge (DE): 'meiner meinung' marks speaker opinion",
        ),
    ];
    for (pat, why) in opinion_patterns {
        if lower.contains(pat) {
            return (Confidence::Opinion, why);
        }
    }

    // ── Verifiable ─────────────────────────────────────────────────────
    // Explicit citation marker takes priority over temporal anchor —
    // a "(source: Smith 2020)" prop has BOTH signals; the citation
    // is the more specific + load-bearing one for the rationale.
    if lower.contains("source:")
        || lower.contains("according to")
        || lower.contains("see:")
        || lower.contains("[ref")
        || lower.contains("doi:")
    {
        return (Confidence::Verifiable, "explicit citation marker present");
    }
    // 4-digit year (1900-2099) → temporal anchor
    if proposition
        .split(|c: char| !c.is_ascii_digit())
        .any(|s| s.len() == 4 && s.starts_with(|c: char| c == '1' || c == '2'))
    {
        return (
            Confidence::Verifiable,
            "temporal anchor: 4-digit year present",
        );
    }
    // Number with unit-shape suffix
    let unit_words = [
        "percent", "%", "kg", "mg", "km", "miles", "meters", "users", "people", "deaths", "cases",
    ];
    if proposition
        .split_whitespace()
        .any(|tok| tok.chars().any(|c| c.is_ascii_digit()))
        && unit_words.iter().any(|u| lower.contains(u))
    {
        return (
            Confidence::Verifiable,
            "quantitative anchor: number with recognised unit",
        );
    }

    // ── Plausible (residual) ──────────────────────────────────────────
    (
        Confidence::Plausible,
        "falsifiable claim without concrete anchor — operator should request a citation",
    )
}

/// QM-19: top-level entry point. Decomposes the input into
/// propositions, classifies each, and rolls up to a verdict.
pub fn assess(text: &str) -> FactCheckReport {
    let propositions: Vec<Proposition> = decompose_propositions(text)
        .into_iter()
        .map(|sentence| {
            let (confidence, why) = classify_confidence(&sentence);
            Proposition {
                text: sentence,
                confidence,
                rationale: why.to_string(),
            }
        })
        .collect();

    let verdict = rollup_verdict(&propositions);
    FactCheckReport {
        propositions,
        verdict,
    }
}

/// Rollup logic. Suspect dominates; otherwise mix of opinion alone
/// or with plausible → NeedsFraming; everything verifiable/plausible
/// without opinion → Clean.
fn rollup_verdict(props: &[Proposition]) -> Verdict {
    if props.is_empty() {
        return Verdict::Clean;
    }
    if props.iter().any(|p| p.confidence == Confidence::Suspect) {
        return Verdict::NeedsRevision;
    }
    if props.iter().any(|p| p.confidence == Confidence::Opinion) {
        return Verdict::NeedsFraming;
    }
    Verdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_splits_on_sentence_terminators() {
        let text = "First sentence. Second one! Third? And one more.";
        let props = decompose_propositions(text);
        assert_eq!(props.len(), 4);
        assert_eq!(props[0], "First sentence.");
        assert_eq!(props[1], "Second one!");
        assert_eq!(props[2], "Third?");
        assert_eq!(props[3], "And one more.");
    }

    #[test]
    fn decompose_skips_tiny_fragments() {
        // "Mr." / "Inc." / single-char endings are parsing artefacts.
        let text = "Hi. Long enough sentence here. .";
        let props = decompose_propositions(text);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0], "Long enough sentence here.");
    }

    #[test]
    fn classify_suspect_on_absolutism() {
        let (c, why) = classify_confidence("Everyone agrees that this is the right call.");
        assert_eq!(c, Confidence::Suspect);
        assert!(why.contains("absolutism"));
    }

    #[test]
    fn classify_suspect_on_slippery_slope() {
        let (c, _) = classify_confidence("Allowing X will inevitably lead to society collapse.");
        assert_eq!(c, Confidence::Suspect);
    }

    #[test]
    fn classify_opinion_on_explicit_hedge() {
        let (c, why) = classify_confidence("I think the new policy is fair.");
        assert_eq!(c, Confidence::Opinion);
        assert!(why.contains("hedge"));
    }

    #[test]
    fn classify_opinion_on_german_hedge() {
        let (c, _) = classify_confidence("Ich denke das Projekt sollte weitermachen.");
        assert_eq!(c, Confidence::Opinion);
    }

    #[test]
    fn classify_verifiable_on_year_anchor() {
        let (c, why) = classify_confidence("The reactor went online in 1986 at Chernobyl.");
        assert_eq!(c, Confidence::Verifiable);
        assert!(why.contains("temporal anchor"));
    }

    #[test]
    fn classify_verifiable_on_citation_marker() {
        let (c, why) =
            classify_confidence("Studies show the effect persists (source: Smith 2020).");
        assert_eq!(c, Confidence::Verifiable);
        assert!(why.contains("citation"));
    }

    #[test]
    fn classify_verifiable_on_quantitative_anchor() {
        let (c, _) = classify_confidence("The vaccine reduced infection by 95 percent.");
        assert_eq!(c, Confidence::Verifiable);
    }

    #[test]
    fn classify_plausible_residual() {
        let (c, why) = classify_confidence("The new framework improves developer productivity.");
        assert_eq!(c, Confidence::Plausible);
        assert!(why.contains("falsifiable"));
    }

    #[test]
    fn suspect_dominates_opinion_when_both_signals_fire() {
        // "Everyone" is absolutism (suspect); "I think" is opinion.
        // Suspect must win — the absolutism is the load-bearing claim
        // shape, not the hedge.
        let (c, _) =
            classify_confidence("I think everyone always tells the truth in this company.");
        assert_eq!(c, Confidence::Suspect);
    }

    #[test]
    fn assess_clean_when_every_prop_verifiable() {
        let report = assess(
            "The reactor went online in 1986 at Chernobyl. Studies show the effect persists (source: Smith 2020).",
        );
        assert_eq!(report.verdict, Verdict::Clean);
        assert_eq!(report.count(Confidence::Verifiable), 2);
    }

    #[test]
    fn assess_needs_framing_when_any_opinion_no_suspect() {
        let report = assess("The project shipped in 2024. I think it was a good idea.");
        assert_eq!(report.verdict, Verdict::NeedsFraming);
        assert_eq!(report.count(Confidence::Opinion), 1);
        assert_eq!(report.count(Confidence::Verifiable), 1);
    }

    #[test]
    fn assess_needs_revision_when_any_suspect() {
        let report = assess("The project shipped in 2024. Everyone agrees it was the right call.");
        assert_eq!(report.verdict, Verdict::NeedsRevision);
        assert_eq!(report.count(Confidence::Suspect), 1);
    }

    #[test]
    fn assess_empty_text_returns_clean_empty() {
        let report = assess("");
        assert!(report.propositions.is_empty());
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = assess("I think the world is flat. Everyone knows it.");
        let json = serde_json::to_string(&report).unwrap();
        let back: FactCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
        // Wire shape: verdict serialises as snake_case.
        assert!(json.contains("\"verdict\":\"needs_revision\""));
    }

    #[test]
    fn confidence_and_verdict_serialise_as_snake_case() {
        // Pin wire form so a future refactor doesn't break the
        // operator-facing `neoth profile fact-check --output json`
        // contract.
        assert_eq!(
            serde_json::to_string(&Confidence::Verifiable).unwrap(),
            "\"verifiable\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::NeedsRevision).unwrap(),
            "\"needs_revision\""
        );
    }
}
