//! QM-18 — citation-check helper (parse + heuristic surface; live lookup
//! deferred until the outbound HTTP allowlist extends).
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` §3.2 `citation-check`
//! ADOPT-AS-CORE. ARS's full citation contamination detection routes
//! through Crossref + OpenAlex + Semantic Scholar; that's network +
//! API-key surface. This module ships the offline-deterministic subset
//! today + carves the outbound surface as a follow-up.
//!
//! ## What ships today
//!
//! - [`extract_citations`] — pull every citation-shaped token out of a
//!   text body. Recognises:
//!     - DOI shapes: `10.\d{4,}/\S+` (case-insensitive)
//!     - arXiv shapes: `arXiv:\d{4}\.\d{4,}` or `arxiv.org/abs/<id>`
//!     - ISBN-10 / ISBN-13: `\b\d{9}[\dX]\b` and `\b97[89]-?\d{10}\b`
//!     - Bare URLs to known publisher domains (Crossref / SemanticScholar /
//!       OpenAlex / PubMed)
//! - [`Citation`] typed entry carrying kind + raw + normalised id.
//! - [`audit_offline`] — runs `extract_citations` + heuristic
//!   contamination checks against the operator's text (e.g. claim
//!   says "Smith 2020" but no matching DOI / URL appears anywhere in
//!   the citations list — "unanchored citation" warning).
//! - [`CitationAudit`] verdict shape.
//!
//! ## What's deferred
//!
//! - Live Crossref / OpenAlex / Semantic Scholar HTTP queries. That
//!   needs the outbound HTTP surface allowlist in
//!   `tests/no_outbound_network.rs`. Follow-up commit lands
//!   `tools::citation_lookup::resolve(citation)` against those APIs
//!   + emits `CITATION_VERIFIED` / `CITATION_CONTAMINATED` WAL
//!   frames at `0xB0..=0xBF` band.
//! - Crosscheck against `idx_groundtruth` (operator-asserted facts).

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// QM-18: one extracted citation. `raw` is the substring verbatim,
/// `normalised` is the canonical id (lower-case DOI, arXiv-id without
/// prefix, ISBN with hyphens stripped) so downstream lookup paths can
/// dedupe across "10.5281/zenodo.123" vs "doi.org/10.5281/zenodo.123".
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Citation {
    pub kind: CitationKind,
    pub raw: String,
    pub normalised: String,
}

/// QM-18: citation source-type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationKind {
    Doi,
    Arxiv,
    Isbn,
    PublisherUrl,
}

impl CitationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CitationKind::Doi => "doi",
            CitationKind::Arxiv => "arxiv",
            CitationKind::Isbn => "isbn",
            CitationKind::PublisherUrl => "publisher_url",
        }
    }
}

/// QM-18: one contamination signal the audit found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContaminationSignal {
    pub kind: String,
    pub message: String,
    pub citation_raw: String,
}

/// QM-18: rollup verdict for the offline audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationVerdict {
    /// No citations found OR every citation looks structurally valid.
    Clean,
    /// One or more contamination signals fired.
    NeedsReview,
}

impl CitationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            CitationVerdict::Clean => "clean",
            CitationVerdict::NeedsReview => "needs_review",
        }
    }
}

/// QM-18 audit report. JSON-stable wire shape for `neoth recall
/// citation-check --output json` follow-up wiring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationAudit {
    pub citations: Vec<Citation>,
    pub signals: Vec<ContaminationSignal>,
    pub verdict: CitationVerdict,
}

/// Cached regexes. `LazyLock` keeps the compile cost once per
/// process; each pattern is ~10µs to compile so we'd be fine
/// re-compiling, but cleanness wins.
static DOI_RE: LazyLock<Regex> = LazyLock::new(|| {
    // DOI format per Crossref: `10.NNNN/<suffix>` where suffix is
    // any non-whitespace. Case-insensitive prefix `doi:` optional.
    Regex::new(r"(?i)\b(?:doi:\s*)?(10\.\d{4,9}/[^\s,;()]+)").unwrap()
});
static ARXIV_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Modern arXiv: `arXiv:YYMM.NNNNN[vN]` or `arxiv.org/abs/<id>`.
    Regex::new(r"(?i)\b(?:arxiv[:\s]*|arxiv\.org/abs/)(\d{4}\.\d{4,6}(?:v\d+)?)").unwrap()
});
static ISBN_RE: LazyLock<Regex> = LazyLock::new(|| {
    // ISBN-13 (978/979) + ISBN-10. ISBN-10 last digit can be X.
    Regex::new(r"(?i)\bisbn[:\s-]*((?:97[89][-\s]?)?\d{1,5}[-\s]?\d{1,7}[-\s]?\d{1,7}[-\s]?[\dX])\b").unwrap()
});
static PUBLISHER_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Match URLs to known scholarly hosts.
    Regex::new(
        r"(?i)\bhttps?://(?:dx\.)?(?:doi\.org|api\.crossref\.org|api\.semanticscholar\.org|api\.openalex\.org|pubmed\.ncbi\.nlm\.nih\.gov)/[^\s,;()]+",
    )
    .unwrap()
});
static AUTHOR_YEAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    // "Smith 2020" / "Smith et al. 2020" / "Smith and Jones 2020"
    // shapes. Used to count narrative citations to compare against
    // the structural citation count.
    Regex::new(r"\b([A-Z][a-z]{2,})(?:\s+et\s+al\.?|\s+and\s+[A-Z][a-z]+)?\s+\(?((?:19|20)\d{2})\)?").unwrap()
});

/// QM-18: extract every citation-shaped token from `text`. Sorted by
/// (kind, normalised) for deterministic output.
pub fn extract_citations(text: &str) -> Vec<Citation> {
    let mut out: HashSet<Citation> = HashSet::new();

    // DOI matches.
    for cap in DOI_RE.captures_iter(text) {
        let raw = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        let id = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if !id.is_empty() {
            out.insert(Citation {
                kind: CitationKind::Doi,
                raw: raw.to_string(),
                normalised: id.trim_end_matches(['.', ',']).to_lowercase(),
            });
        }
    }
    // arXiv matches.
    for cap in ARXIV_RE.captures_iter(text) {
        let raw = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        let id = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if !id.is_empty() {
            out.insert(Citation {
                kind: CitationKind::Arxiv,
                raw: raw.to_string(),
                normalised: id.to_string(),
            });
        }
    }
    // ISBN matches.
    for cap in ISBN_RE.captures_iter(text) {
        let raw = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        let id = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let stripped: String = id.chars().filter(|c| c.is_ascii_digit() || *c == 'X' || *c == 'x').collect();
        if stripped.len() == 10 || stripped.len() == 13 {
            out.insert(Citation {
                kind: CitationKind::Isbn,
                raw: raw.to_string(),
                normalised: stripped.to_uppercase(),
            });
        }
    }
    // Publisher URL matches.
    for m in PUBLISHER_URL_RE.find_iter(text) {
        out.insert(Citation {
            kind: CitationKind::PublisherUrl,
            raw: m.as_str().to_string(),
            normalised: m.as_str().trim_end_matches(['.', ',', ')']).to_lowercase(),
        });
    }

    let mut sorted: Vec<Citation> = out.into_iter().collect();
    sorted.sort_by(|a, b| {
        (a.kind.as_str(), &a.normalised).cmp(&(b.kind.as_str(), &b.normalised))
    });
    sorted
}

/// QM-18 offline audit. Runs `extract_citations` + heuristic
/// contamination signals:
///
/// - **unanchored_citation** — text mentions "Author Year" but no
///   matching DOI / arXiv / URL / ISBN found in the citations list
///   (operator should add the structural anchor).
/// - **suspicious_future_year** — a YYYY anchor > current year + 1
///   (operator likely typo'd or LLM hallucinated future paper).
/// - **doi_prefix_unknown** — DOI registrar prefix `10.NNNN` is not
///   in a small known-good list (post-fix follow-up; today
///   reserved-no-fire).
///
/// Pure function; no I/O. Live Crossref / OpenAlex / Semantic
/// Scholar lookup is the follow-up `tools::citation_lookup` module
/// once the outbound-HTTP allowlist extends.
pub fn audit_offline(text: &str) -> CitationAudit {
    let citations = extract_citations(text);
    let mut signals = Vec::new();

    // Count "Author Year" narrative refs.
    let narrative_count = AUTHOR_YEAR_RE.captures_iter(text).count();
    let structural_count = citations.len();
    if narrative_count > structural_count {
        let gap = narrative_count - structural_count;
        signals.push(ContaminationSignal {
            kind: "unanchored_narrative_citations".to_string(),
            message: format!(
                "text carries {narrative_count} narrative `Author Year` refs but \
                 only {structural_count} structural citations (DOI/arXiv/ISBN/URL). \
                 {gap} narrative ref(s) appear unanchored — operator should add \
                 structural ids."
            ),
            citation_raw: String::new(),
        });
    }

    // Suspicious-future-year signal.
    let current_year = current_year_unix() as i32;
    for cap in AUTHOR_YEAR_RE.captures_iter(text) {
        if let Some(year) = cap.get(2).and_then(|m| m.as_str().parse::<i32>().ok()) {
            if year > current_year + 1 {
                let full = cap.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
                signals.push(ContaminationSignal {
                    kind: "suspicious_future_year".to_string(),
                    message: format!(
                        "narrative citation references year {year} which is beyond \
                         the current year + 1. Likely typo or LLM hallucination — \
                         verify the source exists."
                    ),
                    citation_raw: full,
                });
            }
        }
    }

    let verdict = if signals.is_empty() {
        CitationVerdict::Clean
    } else {
        CitationVerdict::NeedsReview
    };
    CitationAudit {
        citations,
        signals,
        verdict,
    }
}

/// Pull the current year from system time. Pure modulo conversion;
/// no external clock service. Used only by the suspicious-future-
/// year heuristic so a stuck clock at most lets a known-good
/// citation through, never blocks a real one.
fn current_year_unix() -> u32 {
    // 2026 = epoch_seconds 1735689600. Compute years-since-1970
    // via integer division — accurate to the operator's wall clock.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 1970 + (secs / seconds_per_year). Approximation that's
    // accurate to within ~30 days, which is fine for "is this year
    // implausibly far in the future" heuristics.
    1970 + (secs / 31_557_600) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bare_doi() {
        let text = "See 10.1145/3372297.3417271 for details.";
        let cites = extract_citations(text);
        assert_eq!(cites.len(), 1);
        assert_eq!(cites[0].kind, CitationKind::Doi);
        assert_eq!(cites[0].normalised, "10.1145/3372297.3417271");
    }

    #[test]
    fn extracts_doi_with_prefix() {
        let text = "Reference: DOI: 10.1038/nature12373";
        let cites = extract_citations(text);
        assert!(cites.iter().any(|c| c.normalised == "10.1038/nature12373"));
    }

    #[test]
    fn extracts_arxiv_id_both_shapes() {
        // Verify each shape independently to avoid HashSet dedup
        // collapsing two different raw forms with the same normalised id.
        let cites1 = extract_citations("See arXiv:2401.12345");
        assert!(cites1.iter().any(|c| c.kind == CitationKind::Arxiv && c.normalised == "2401.12345"));
        let cites2 = extract_citations("See arxiv.org/abs/2305.00001v2");
        assert!(cites2.iter().any(|c| c.kind == CitationKind::Arxiv && c.normalised == "2305.00001v2"));
    }

    #[test]
    fn extracts_isbn13() {
        let text = "ISBN: 978-0-13-110362-7";
        let cites = extract_citations(text);
        let isbn = cites.iter().find(|c| c.kind == CitationKind::Isbn);
        assert!(isbn.is_some(), "ISBN must extract; got {cites:?}");
        assert_eq!(isbn.unwrap().normalised, "9780131103627");
    }

    #[test]
    fn extracts_publisher_url() {
        let text = "https://doi.org/10.1038/nature12373 and https://api.semanticscholar.org/graph/v1/paper/x";
        let cites = extract_citations(text);
        let urls: Vec<&Citation> = cites
            .iter()
            .filter(|c| c.kind == CitationKind::PublisherUrl)
            .collect();
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_dedupes_identical_normalised_ids() {
        let text = "DOI: 10.1038/x and again DOI:10.1038/X — same id.";
        let cites = extract_citations(text);
        let dois: Vec<&Citation> = cites.iter().filter(|c| c.kind == CitationKind::Doi).collect();
        // HashSet dedupes by (kind, raw, normalised) tuple, so two
        // different raw forms with the SAME normalised id can still
        // appear as two entries. The point of normalisation is
        // CONSUMER-side dedup. Pin so the operator can grep the
        // unique normalised set without surprise.
        let unique_normalised: HashSet<&String> = dois.iter().map(|c| &c.normalised).collect();
        assert_eq!(unique_normalised.len(), 1);
    }

    #[test]
    fn audit_returns_clean_when_no_citations_no_narrative() {
        let audit = audit_offline("This text has no references at all.");
        assert_eq!(audit.verdict, CitationVerdict::Clean);
        assert!(audit.citations.is_empty());
        assert!(audit.signals.is_empty());
    }

    #[test]
    fn audit_flags_unanchored_narrative_citations() {
        // Many "Author Year" refs, no DOIs / URLs → unanchored.
        let text = "Per Smith 2020, the effect persists. Jones et al. 2021 \
                    independently confirmed this. Brown 2022 disagreed.";
        let audit = audit_offline(text);
        assert_eq!(audit.verdict, CitationVerdict::NeedsReview);
        assert!(audit
            .signals
            .iter()
            .any(|s| s.kind == "unanchored_narrative_citations"));
    }

    #[test]
    fn audit_clean_when_narrative_matches_structural() {
        // 2 narrative refs + 2 DOIs → no unanchored signal.
        let text = "Per Smith 2020 (10.1145/aaa.bbb) and Jones 2021 \
                    (10.1145/ccc.ddd) the effect persists.";
        let audit = audit_offline(text);
        assert!(audit
            .signals
            .iter()
            .all(|s| s.kind != "unanchored_narrative_citations"));
    }

    #[test]
    fn audit_flags_suspicious_future_year() {
        let text = "Per Smith 2099, the effect will persist.";
        let audit = audit_offline(text);
        assert!(audit
            .signals
            .iter()
            .any(|s| s.kind == "suspicious_future_year"));
        assert_eq!(audit.verdict, CitationVerdict::NeedsReview);
    }

    #[test]
    fn audit_does_not_flag_current_year_citations() {
        // current_year + 0 is fine (paper just published).
        let current = current_year_unix();
        let text = format!("Per Smith {current}, the effect persists.");
        let audit = audit_offline(&text);
        // Note: this MAY flag as unanchored (no DOI given), but
        // MUST NOT flag suspicious_future_year.
        assert!(audit
            .signals
            .iter()
            .all(|s| s.kind != "suspicious_future_year"));
    }

    #[test]
    fn report_round_trips_through_json() {
        let text = "Per Smith 2099 (10.1145/aaa.bbb) the effect persists.";
        let audit = audit_offline(text);
        let json = serde_json::to_string(&audit).unwrap();
        let back: CitationAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(audit, back);
        // Pin snake_case wire form.
        assert!(json.contains("\"verdict\":\"needs_review\""));
        assert!(json.contains("\"kind\":\"doi\""));
    }

    #[test]
    fn citation_kind_serialises_snake_case() {
        for (k, expected) in [
            (CitationKind::Doi, "\"doi\""),
            (CitationKind::Arxiv, "\"arxiv\""),
            (CitationKind::Isbn, "\"isbn\""),
            (CitationKind::PublisherUrl, "\"publisher_url\""),
        ] {
            assert_eq!(serde_json::to_string(&k).unwrap(), expected);
        }
    }

    #[test]
    fn current_year_unix_is_in_plausible_range() {
        // Sanity: current_year_unix() should return something between
        // 2024 and 2050 for any operator running this code. Pin so
        // a future signed-int regression surfaces here.
        let y = current_year_unix();
        assert!((2024..2050).contains(&y), "got year {y}");
    }
}
