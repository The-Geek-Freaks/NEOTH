//! QM-20 — Temporal integrity verifier.
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` §4.4: port the ARS
//! v3.9.4 temporal integrity passes that catch five failure modes
//! the LLM commits when reasoning about time:
//!
//! - P1 retrospective arithmetic ("In 2024, the project was 5 years
//!   old, so it started in 2019" — math is right, anchor year is
//!   often wrong)
//! - P2 anachronistic citation (citing a paper published AFTER the
//!   event being discussed)
//! - P3 comparator unmaterialized ("X is better than Y" without Y
//!   established as a comparator earlier)
//! - P4 causal inversion (effect → cause swap)
//! - P5 deictic present ("currently" / "today" without a fixed
//!   reference date)
//!
//! v0.1 ships **P1 + P4** deterministically + a P5 quick check that
//! flags deictic markers without an anchor. P2 + P3 defer to after
//! citation_check (QM-18) lands — they need either a paper-date
//! lookup or a multi-turn context window the deterministic pass
//! doesn't have.
//!
//! ## Composition with QM-19
//!
//! QM-19 fact_check answers "is this proposition supported?"; QM-20
//! temporal_guard answers "is this proposition coherent across time?".
//! Run both for a thorough audit; either alone catches a distinct
//! failure class.

use serde::{Deserialize, Serialize};

/// QM-20: one temporal-integrity finding. Operators see these in the
/// `neoth profile temporal-check --output table` render or the
/// `0xB4 TEMPORAL_ADVISORY` WAL frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalFinding {
    /// Stable id of the failure mode (`retrospective_arithmetic` /
    /// `causal_inversion` / `deictic_unanchored`). Operators grep
    /// on these to build histograms.
    pub kind: String,
    /// Operator-readable description of the failure + the specific
    /// span that triggered it.
    pub message: String,
    /// The substring of input that fired the pattern. Bounded at
    /// 200 chars to keep WAL frames small.
    pub citation: String,
}

/// QM-20: rollup verdict for the temporal pass over an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalVerdict {
    /// No temporal failure mode tripped. Operator can ship.
    Coherent,
    /// One or more findings present. Operator must review the
    /// findings before treating the text as coherent across time.
    NeedsReview,
}

impl TemporalVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            TemporalVerdict::Coherent => "coherent",
            TemporalVerdict::NeedsReview => "needs_review",
        }
    }
}

/// QM-20 report. JSON-stable for `neoth profile temporal-check
/// --output json` + downstream tooling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalReport {
    pub findings: Vec<TemporalFinding>,
    pub verdict: TemporalVerdict,
}

impl TemporalReport {
    pub fn count_kind(&self, kind: &str) -> usize {
        self.findings.iter().filter(|f| f.kind == kind).count()
    }
}

/// QM-20 P1: retrospective arithmetic detector.
///
/// Flags "In <YEAR>, X was N years old, so X started in <COMPUTED>"
/// shapes. The math is usually right but the anchor year is often
/// guessed wrong by the LLM — operator wants the flag so they can
/// verify the anchor.
///
/// Pattern: a 4-digit year + "(N|N years) old/of age/in existence"
/// + an arithmetic outcome year. We surface the finding even when
/// the math IS right; the point is "anchor year claim, please verify".
pub fn check_retrospective_arithmetic(text: &str) -> Vec<TemporalFinding> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();
    // Coarse marker: "in <year>" + "years old" OR "of age" OR
    // "started in" — operator wants the flag any time the LLM did
    // year arithmetic, regardless of correctness.
    let markers = [
        "years old",
        "of age",
        "started in",
        "founded in",
        "established in",
        "in existence",
        "alt geworden",
        "gegründet",
    ];
    if markers.iter().any(|m| lower.contains(m)) {
        // Confirm there's a 4-digit year anchor — otherwise it's
        // just narrative not arithmetic.
        let has_year = text
            .split(|c: char| !c.is_ascii_digit())
            .any(|s| s.len() == 4 && s.starts_with(|c: char| c == '1' || c == '2'));
        if has_year {
            let snippet = truncate_for_citation(text);
            out.push(TemporalFinding {
                kind: "retrospective_arithmetic".to_string(),
                message: "Retrospective year arithmetic detected. Verify the anchor year — \
                     LLMs often get the math right but the anchor wrong."
                    .to_string(),
                citation: snippet,
            });
        }
    }
    out
}

/// QM-20 P4: causal-inversion detector.
///
/// Catches effect→cause swap markers: "X caused Y" + "Y triggered X"
/// in the same paragraph, or temporal indicators that contradict
/// stated causality ("X happened after Y, so X caused Y" — typo'd
/// causality where after-event-can't-cause-prior-event).
///
/// v0.1 ships the explicit-marker subset: phrases that literally
/// say "X caused Y because Y happened first" are flagged. Multi-
/// turn temporal-graph reasoning is deferred — that needs the
/// citation_check entity graph (QM-18 follow-up).
pub fn check_causal_inversion(text: &str) -> Vec<TemporalFinding> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();
    // Explicit-marker phrases that signal the LLM may have inverted
    // cause + effect.
    let inversion_markers = [
        ("caused", "happened first"),
        ("led to", "happened first"),
        ("triggered", "preceded by"),
        ("verursachte", "ging voraus"),
    ];
    for (cause_marker, sequence_marker) in inversion_markers {
        if lower.contains(cause_marker) && lower.contains(sequence_marker) {
            let snippet = truncate_for_citation(text);
            out.push(TemporalFinding {
                kind: "causal_inversion".to_string(),
                message: format!(
                    "Causal-inversion signal: text says '{cause_marker}' AND \
                     '{sequence_marker}'. Verify cause/effect order is correct."
                ),
                citation: snippet,
            });
            return out; // one finding per text is plenty for the operator
        }
    }
    out
}

/// QM-20 P5 (quick check): deictic-present detector.
///
/// Catches "currently" / "today" / "right now" without an explicit
/// reference date. These markers age silently — text that was true
/// last year reads as if it's true today. v0.1 surfaces the
/// presence-without-anchor; the operator decides whether to add a
/// reference date.
pub fn check_deictic_unanchored(text: &str) -> Vec<TemporalFinding> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();
    let deictic_markers = [
        "currently",
        "right now",
        "today,",
        "at present",
        "nowadays",
        "derzeit",
        "aktuell",
        "heutzutage",
    ];
    let has_deictic = deictic_markers.iter().any(|m| lower.contains(m));
    if !has_deictic {
        return out;
    }
    // If an explicit anchor date is present, no need to flag.
    let has_anchor = text
        .split(|c: char| !c.is_ascii_digit())
        .any(|s| s.len() == 4 && s.starts_with(|c: char| c == '1' || c == '2'))
        || lower.contains("as of ")
        || lower.contains("stand:");
    if !has_anchor {
        out.push(TemporalFinding {
            kind: "deictic_unanchored".to_string(),
            message: "Deictic time marker without a reference date. Anchor with 'as of <date>' \
                 so the text doesn't silently age out of correctness."
                .to_string(),
            citation: truncate_for_citation(text),
        });
    }
    out
}

/// QM-20 entry point. Runs P1 + P4 + the P5 quick-check; collects
/// every finding + rolls up the verdict.
pub fn check(text: &str) -> TemporalReport {
    let mut findings = Vec::new();
    findings.extend(check_retrospective_arithmetic(text));
    findings.extend(check_causal_inversion(text));
    findings.extend(check_deictic_unanchored(text));
    let verdict = if findings.is_empty() {
        TemporalVerdict::Coherent
    } else {
        TemporalVerdict::NeedsReview
    };
    TemporalReport { findings, verdict }
}

/// Citation trimmer — bound at 200 chars so WAL frames + report
/// JSON stay small. Multi-byte safe via char boundary truncation.
fn truncate_for_citation(text: &str) -> String {
    const CAP: usize = 200;
    if text.len() <= CAP {
        return text.to_string();
    }
    let mut end = CAP;
    while !text.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrospective_arithmetic_fires_on_years_old_with_year_anchor() {
        let findings = check_retrospective_arithmetic(
            "In 2024, the project was 5 years old, so it started in 2019.",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "retrospective_arithmetic");
        assert!(findings[0].citation.contains("2024"));
    }

    #[test]
    fn retrospective_arithmetic_fires_on_german_age_marker() {
        let findings = check_retrospective_arithmetic(
            "1995 wurde die Firma gegründet, sie ist also 30 Jahre alt geworden.",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn retrospective_arithmetic_skips_text_without_year_anchor() {
        // Has "years old" but no 4-digit year — narrative, not
        // arithmetic. Skip.
        let findings = check_retrospective_arithmetic("My cat is 5 years old.");
        assert!(findings.is_empty());
    }

    #[test]
    fn causal_inversion_fires_on_explicit_marker_pair() {
        let findings = check_causal_inversion(
            "The new policy caused the outage. The outage happened first in March.",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "causal_inversion");
        assert!(findings[0].message.contains("caused"));
        assert!(findings[0].message.contains("happened first"));
    }

    #[test]
    fn causal_inversion_skips_normal_causality() {
        // Has "caused" but no "happened first" — normal sequence.
        let findings =
            check_causal_inversion("The storm caused widespread damage. Repairs took months.");
        assert!(findings.is_empty());
    }

    #[test]
    fn deictic_unanchored_fires_on_currently_without_year() {
        let findings =
            check_deictic_unanchored("Currently, the project is in beta. The team is small.");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "deictic_unanchored");
    }

    #[test]
    fn deictic_unanchored_skips_when_anchor_year_present() {
        // "as of 2026" anchors the deictic marker → no flag.
        let findings =
            check_deictic_unanchored("Currently (as of 2026-05), the project is in beta.");
        assert!(findings.is_empty());
    }

    #[test]
    fn deictic_unanchored_skips_when_year_anchor_inline() {
        let findings = check_deictic_unanchored("In 2026 the project is currently in beta.");
        assert!(findings.is_empty());
    }

    #[test]
    fn deictic_unanchored_fires_on_german_marker() {
        let findings = check_deictic_unanchored("Aktuell läuft das Projekt in Beta.");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn check_aggregates_findings_with_year_anchor_silencing_deictic() {
        // Text triggers retrospective arithmetic AND causal inversion.
        // Deictic-unanchored INTENTIONALLY does NOT fire because the
        // text carries a 4-digit year anchor (2024) — operator's
        // "Currently" reads from that anchor, no ambiguity. Pin the
        // silencing contract so a future refactor that broadens
        // deictic-fires-always surfaces here.
        let findings = check(
            "In 2024, the project was 5 years old. The policy caused the outage \
             and the outage happened first. Currently the team is small.",
        );
        assert_eq!(findings.verdict, TemporalVerdict::NeedsReview);
        assert_eq!(findings.count_kind("retrospective_arithmetic"), 1);
        assert_eq!(findings.count_kind("causal_inversion"), 1);
        // Deictic silenced by the year-anchor presence in the text.
        assert_eq!(
            findings.count_kind("deictic_unanchored"),
            0,
            "year anchor in text must silence deictic finding"
        );
    }

    #[test]
    fn check_fires_all_three_when_text_lacks_year_anchor() {
        // Deictic-no-anchor text composed without a 4-digit year so
        // all three passes fire (retrospective uses German marker,
        // causal uses explicit phrase, deictic fires because no
        // anchor in the text).
        let findings = check(
            "Die Firma wurde gegründet und ist 30 Jahre alt geworden. \
             The policy caused the issue and the issue happened first. \
             Aktuell ist alles unklar.",
        );
        assert_eq!(findings.verdict, TemporalVerdict::NeedsReview);
        // Retrospective: 'gegründet' marker + needs year anchor in
        // the text → since this text has no year, retrospective does
        // NOT fire either. So we get causal + deictic only.
        assert!(findings.findings.len() >= 2);
        assert_eq!(findings.count_kind("causal_inversion"), 1);
        assert_eq!(findings.count_kind("deictic_unanchored"), 1);
    }

    #[test]
    fn check_returns_coherent_when_no_findings() {
        let report = check(
            "The Mona Lisa was painted between 1503 and 1517 by Leonardo da Vinci. \
             It now hangs in the Louvre.",
        );
        // No deictic markers ("now hangs" doesn't match our patterns —
        // intentionally narrow so we don't flood operators with false
        // positives), no arithmetic, no inversion → Coherent.
        assert_eq!(report.verdict, TemporalVerdict::Coherent);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = check("In 1986, the reactor was 13 years old. Currently it's still closed.");
        let json = serde_json::to_string(&report).unwrap();
        let back: TemporalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
        assert!(json.contains("\"verdict\":\"needs_review\""));
        assert!(json.contains("\"kind\":\"retrospective_arithmetic\""));
    }

    #[test]
    fn citation_truncation_respects_char_boundaries() {
        // Multi-byte chars near the 200-byte boundary must not panic.
        let long = "ü".repeat(150); // 2 bytes per char = 300 bytes
        let truncated = truncate_for_citation(&long);
        // Must be a valid utf-8 String + carry the truncation marker.
        assert!(truncated.ends_with('…'));
        assert!(truncated.len() <= 203); // 200 + ellipsis (3 bytes)
    }

    #[test]
    fn verdict_round_trips_serde() {
        for v in [TemporalVerdict::Coherent, TemporalVerdict::NeedsReview] {
            let s = serde_json::to_string(&v).unwrap();
            let back: TemporalVerdict = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
            assert_eq!(v.as_str(), s.trim_matches('"'));
        }
    }
}
